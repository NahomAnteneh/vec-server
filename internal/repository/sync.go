package repository

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// CommitInfo stores commit data extracted from git log
type CommitInfo struct {
	Hash           string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Message        string
	ParentHashes   []string
	CommitDate     time.Time
}

// SyncManager handles synchronization between filesystem repositories and database
type SyncManager struct {
	manager       *Manager
	commitService models.CommitService
	branchService models.BranchService
	repoService   models.RepositoryService
}

// NewSyncManager creates a new sync manager
func NewSyncManager(manager *Manager, commitService models.CommitService,
	branchService models.BranchService, repoService models.RepositoryService) *SyncManager {
	return &SyncManager{
		manager:       manager,
		commitService: commitService,
		branchService: branchService,
		repoService:   repoService,
	}
}

// SyncRepository synchronizes a repository's data with the database
func (sm *SyncManager) SyncRepository(repo *models.Repository) error {
	// Sync branches
	if err := sm.SyncBranches(repo); err != nil {
		return fmt.Errorf("error syncing branches: %w", err)
	}

	// Sync commits
	if err := sm.SyncCommits(repo); err != nil {
		return fmt.Errorf("error syncing commits: %w", err)
	}

	return nil
}

// SyncBranches synchronizes branches for a repository
func (sm *SyncManager) SyncBranches(repo *models.Repository) error {
	// Get all branches from the filesystem
	refs, err := sm.manager.GetRefs(repo)
	if err != nil {
		return err
	}

	// Track which branches we've processed
	processedBranches := make(map[string]bool)

	// Process each branch reference
	for refName, commitHash := range refs {
		// Only process head references (branches)
		if !strings.HasPrefix(refName, "refs/heads/") {
			continue
		}

		branchName := strings.TrimPrefix(refName, "refs/heads/")
		processedBranches[branchName] = true

		// Check if this branch already exists in the database
		branch, err := sm.branchService.GetByName(repo.ID, branchName)
		if err != nil {
			// Branch doesn't exist, create it
			isDefault := false
			// Check if this is the default branch by looking at HEAD
			headRef, headErr := sm.manager.GetRef(repo, "HEAD")
			if headErr == nil && headRef.Symbolic && headRef.Value == refName {
				isDefault = true
			}

			branch = &models.Branch{
				Name:         branchName,
				RepositoryID: repo.ID,
				CommitHash:   commitHash,
				IsDefault:    isDefault,
			}
			if err := sm.branchService.Create(branch); err != nil {
				return fmt.Errorf("error creating branch %s: %w", branchName, err)
			}
		} else {
			// Branch exists, update it if needed
			if branch.CommitHash != commitHash {
				branch.CommitHash = commitHash
				if err := sm.branchService.Update(branch); err != nil {
					return fmt.Errorf("error updating branch %s: %w", branchName, err)
				}
			}
		}
	}

	// Get all branches from the database for this repo
	dbBranches, err := sm.branchService.ListByRepository(repo.ID)
	if err != nil {
		return err
	}

	// Delete branches that no longer exist in the filesystem
	for _, branch := range dbBranches {
		if !processedBranches[branch.Name] {
			if err := sm.branchService.Delete(repo.ID, branch.Name); err != nil {
				return fmt.Errorf("error deleting branch %s: %w", branch.Name, err)
			}
		}
	}

	return nil
}

// SyncCommits synchronizes commits for a repository
func (sm *SyncManager) SyncCommits(repo *models.Repository) error {
	// Get all branches
	branches, err := sm.branchService.ListByRepository(repo.ID)
	if err != nil {
		return err
	}

	// Process commits from each branch
	for _, branch := range branches {
		commits, err := sm.getCommitsForBranch(repo, branch.Name)
		if err != nil {
			return fmt.Errorf("error getting commits for branch %s: %w", branch.Name, err)
		}

		// Store each commit in the database
		for _, commitInfo := range commits {
			// Check if commit already exists
			_, err := sm.commitService.GetByHash(repo.ID, commitInfo.Hash)
			if err == nil {
				// Commit already exists, skip
				continue
			}

			// Create the commit
			commit := &models.Commit{
				Hash:           commitInfo.Hash,
				RepositoryID:   repo.ID,
				AuthorName:     commitInfo.AuthorName,
				AuthorEmail:    commitInfo.AuthorEmail,
				CommitterName:  commitInfo.CommitterName,
				CommitterEmail: commitInfo.CommitterEmail,
				Message:        commitInfo.Message,
				ParentHashes:   strings.Join(commitInfo.ParentHashes, ","),
				CommitDate:     commitInfo.CommitDate,
			}

			if err := sm.commitService.Create(commit); err != nil {
				return fmt.Errorf("error creating commit %s: %w", commitInfo.Hash, err)
			}
		}
	}

	return nil
}

// getCommitsForBranch retrieves commit information for a branch using git log
func (sm *SyncManager) getCommitsForBranch(repo *models.Repository, branchName string) ([]CommitInfo, error) {
	// We'll use the git command directly for this
	gitArgs := []string{
		"-C", repo.Path,
		"log",
		"--format=%H%n%an%n%ae%n%cn%n%ce%n%P%n%at%n%B%n--VEC-COMMIT-END--",
		"refs/heads/" + branchName,
	}

	cmd := exec.Command("git", gitArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running git log: %w", err)
	}

	// Parse the output
	return parseCommitLog(out.String())
}

// parseCommitLog parses the output of git log to extract commit information
func parseCommitLog(logOutput string) ([]CommitInfo, error) {
	commits := []CommitInfo{}
	scanner := bufio.NewScanner(strings.NewReader(logOutput))

	var currentCommit *CommitInfo
	messageLines := []string{}
	lineCount := 0

	for scanner.Scan() {
		line := scanner.Text()

		if line == "--VEC-COMMIT-END--" {
			if currentCommit != nil {
				currentCommit.Message = strings.TrimSpace(strings.Join(messageLines, "\n"))
				commits = append(commits, *currentCommit)
				currentCommit = nil
				messageLines = []string{}
				lineCount = 0
			}
			continue
		}

		if currentCommit == nil {
			currentCommit = &CommitInfo{}
			lineCount = 0
		}

		switch lineCount {
		case 0:
			currentCommit.Hash = line
		case 1:
			currentCommit.AuthorName = line
		case 2:
			currentCommit.AuthorEmail = line
		case 3:
			currentCommit.CommitterName = line
		case 4:
			currentCommit.CommitterEmail = line
		case 5:
			if line != "" {
				currentCommit.ParentHashes = strings.Split(line, " ")
			} else {
				currentCommit.ParentHashes = []string{}
			}
		case 6:
			timestamp, err := parseUnixTimestamp(line)
			if err != nil {
				return nil, fmt.Errorf("error parsing commit date: %w", err)
			}
			currentCommit.CommitDate = timestamp
		default:
			messageLines = append(messageLines, line)
		}

		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return commits, nil
}

// parseUnixTimestamp converts a unix timestamp string to time.Time
func parseUnixTimestamp(timestamp string) (time.Time, error) {
	i, err := parseInt64(timestamp)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(i, 0), nil
}

// parseInt64 parses a string into an int64
func parseInt64(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty string")
	}

	var result int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid character in int64: %c", c)
		}
		result = result*10 + int64(c-'0')
	}
	return result, nil
}
