package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"gorm.io/gorm"
)

// ParsedCommit holds data extracted from a core.Commit object, adapted for DB storage.
// Timestamps are parsed into AuthoredAt and CommittedAt.
type ParsedCommit struct {
	Hash           string   // The hash of the commit object itself
	TreeHash       string   // Hash of the tree object
	ParentHashes   []string // Hashes of parent commits
	AuthorName     string
	AuthorEmail    string
	AuthoredAt     time.Time
	CommitterName  string
	CommitterEmail string
	CommittedAt    time.Time
	Message        string
}

// SyncManager handles synchronization between filesystem repositories and database
type SyncManager struct {
	manager       *Manager
	commitService models.CommitService
	branchService models.BranchService
}

// NewSyncManager creates a new sync manager
func NewSyncManager(manager *Manager, commitService models.CommitService,
	branchService models.BranchService) *SyncManager {
	return &SyncManager{
		manager:       manager,
		commitService: commitService,
		branchService: branchService,
	}
}

// parseGitStyleSignature extracts name and email from a "Name <email>" string.
func parseGitStyleSignature(sigLine string) (name, email string, err error) {
	if sigLine == "" {
		return "", "", fmt.Errorf("empty signature line")
	}
	lastLt := strings.LastIndex(sigLine, "<")
	lastGt := strings.LastIndex(sigLine, ">")

	if lastLt == -1 || lastGt == -1 || lastGt < lastLt {
		// Fallback: if no email tag, assume the whole line is the name
		// This might happen if core.Commit.Author/Committer is just a name
		return strings.TrimSpace(sigLine), "", nil
	}

	name = strings.TrimSpace(sigLine[:lastLt])
	email = sigLine[lastLt+1 : lastGt]
	if name == "" && email == "" {
		// If parsing results in empty name and email, but sigLine was not empty, treat whole as name.
		// This can happen for malformed strings like "<>"
		return strings.TrimSpace(sigLine), "", nil
	}
	return name, email, nil
}

// adaptCoreCommit converts a *core.Commit to a *ParsedCommit.
func adaptCoreCommit(coreCommit *core.Commit) (*ParsedCommit, error) {
	if coreCommit == nil {
		return nil, fmt.Errorf("cannot adapt nil core.Commit")
	}

	authorName, authorEmail, err := parseGitStyleSignature(coreCommit.Author)
	if err != nil {
		// Log or decide if this is a fatal error. For now, we'll try to proceed.
		// fmt.Printf("Warning: could not parse author signature '%s': %v\\n", coreCommit.Author, err)
	}

	committerName, committerEmail, err := parseGitStyleSignature(coreCommit.Committer)
	if err != nil {
		// fmt.Printf("Warning: could not parse committer signature '%s': %v\\n", coreCommit.Committer, err)
	}

	// If committer fields are empty and author fields are not, default committer to author
	if committerName == "" && committerEmail == "" && (authorName != "" || authorEmail != "") {
		committerName = authorName
		committerEmail = authorEmail
	}
	// If author fields are empty and committer fields are not, default author to committer (less common)
	if authorName == "" && authorEmail == "" && (committerName != "" || committerEmail != "") {
		authorName = committerName
		authorEmail = committerEmail
	}

	return &ParsedCommit{
		Hash:           coreCommit.CommitID, // Already the correct hash from core.GetCommit
		TreeHash:       coreCommit.Tree,
		ParentHashes:   coreCommit.Parents,
		AuthorName:     authorName,
		AuthorEmail:    authorEmail,
		AuthoredAt:     coreCommit.Timestamp, // core.Commit has one timestamp
		CommitterName:  committerName,
		CommitterEmail: committerEmail,
		CommittedAt:    coreCommit.Timestamp, // Use the same timestamp for committer
		Message:        coreCommit.Message,
	}, nil
}

// SyncRepository synchronizes a repository's data with the database
func (sm *SyncManager) SynchronizeRepository(repoModel *models.Repository, ownerUser *models.User) error {
	// repoModel.Path should be set by the caller, or we use manager.GetRepoPath
	repoPath, err := sm.manager.GetRepoPath(ownerUser.Username, repoModel.Name)
	if err != nil {
		return fmt.Errorf("could not get repo path for %s/%s: %w", ownerUser.Username, repoModel.Name, err)
	}

	coreRepo := sm.manager.getCoreRepository(repoPath) // This should return *core.Repository

	// Sync branches first to establish current heads
	if err := sm.syncBranches(coreRepo, repoModel); err != nil {
		return fmt.Errorf("error syncing branches for %s: %w", repoPath, err)
	}

	// Sync commits, traversing from branch heads
	if err := sm.syncCommits(coreRepo, repoModel); err != nil {
		return fmt.Errorf("error syncing commits for %s: %w", repoPath, err)
	}

	return nil
}

// syncBranches synchronizes branches for a repository
func (sm *SyncManager) syncBranches(coreRepo *core.Repository, repoModel *models.Repository) error {
	branchMap, err := sm.manager.GetBranches(coreRepo.Root) // Uses coreRepo.Root
	if err != nil {
		// If no branches found (e.g. empty repo), it might not be an error, could be core.ErrNotFound or similar
		// core.IsErrNotFound might be more robust if available and applicable
		if core.IsErrNotFound(err) || strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such file or directory") {
			// This can happen for an empty repository, not necessarily an error for syncBranches itself.
			sm.manager.logger.Printf("No branches found in filesystem for %s, possibly empty repo.", coreRepo.Root)
			branchMap = make(map[string]string) // Proceed with empty map
		} else {
			return fmt.Errorf("failed to get branches from manager: %w", err)
		}
	}

	processedBranches := make(map[string]bool)

	// Determine default branch from HEAD
	defaultBranchName := ""
	headRefContent, err := coreRepo.ReadHead() // Assumes core.Repository has ReadHead()
	if err == nil && strings.HasPrefix(headRefContent, "ref: refs/heads/") {
		defaultBranchName = strings.TrimPrefix(headRefContent, "ref: refs/heads/")
	} else if err != nil && !core.IsErrNotFound(err) { // Log error if it's not a simple "not found"
		sm.manager.logger.Printf("Warning: could not read HEAD for repo %s: %v", coreRepo.Root, err)
	}

	for branchName, commitHash := range branchMap {
		processedBranches[branchName] = true

		dbBranch, err := sm.branchService.GetByName(repoModel.ID, branchName)
		if errors.Is(err, gorm.ErrRecordNotFound) { // Branch doesn't exist in DB, create it
			newBranch := &models.Branch{
				Name:         branchName,
				RepositoryID: repoModel.ID,
				CommitID:     commitHash,
				IsDefault:    branchName == defaultBranchName,
			}
			if err := sm.branchService.Create(newBranch); err != nil {
				return fmt.Errorf("error creating branch %s in DB: %w", branchName, err)
			}
		} else if err != nil { // Other error fetching branch
			return fmt.Errorf("error fetching branch %s from DB: %w", branchName, err)
		} else { // Branch exists, update if needed
			needsUpdate := false
			if dbBranch.CommitID != commitHash {
				dbBranch.CommitID = commitHash
				needsUpdate = true
			}
			if dbBranch.IsDefault != (branchName == defaultBranchName) {
				dbBranch.IsDefault = (branchName == defaultBranchName)
				needsUpdate = true
			}
			if needsUpdate {
				if err := sm.branchService.Update(dbBranch); err != nil {
					return fmt.Errorf("error updating branch %s in DB: %w", branchName, err)
				}
			}
		}
	}

	dbBranches, err := sm.branchService.ListByRepository(repoModel.ID)
	if err != nil {
		return fmt.Errorf("failed to list branches from DB for repo ID %d: %w", repoModel.ID, err)
	}

	for _, dbBranch := range dbBranches {
		if !processedBranches[dbBranch.Name] {
			if err := sm.branchService.Delete(repoModel.ID, dbBranch.Name); err != nil {
				return fmt.Errorf("error deleting branch %s from DB: %w", dbBranch.Name, err)
			}
		}
	}
	return nil
}

// syncCommits synchronizes commits for a repository by traversing from branch heads.
func (sm *SyncManager) syncCommits(coreRepo *core.Repository, repoModel *models.Repository) error {
	dbBranches, err := sm.branchService.ListByRepository(repoModel.ID)
	if err != nil {
		return fmt.Errorf("failed to list branches from DB for commit sync: %w", err)
	}

	visited := make(map[string]bool) // To keep track of processed commits
	queue := []string{}              // Commit hashes to process

	for _, branch := range dbBranches {
		if branch.CommitID != "" && !visited[branch.CommitID] {
			queue = append(queue, branch.CommitID)
			visited[branch.CommitID] = true // Mark as visited when added to queue
		}
	}

	if len(queue) == 0 {
		sm.manager.logger.Printf("No commits to sync for repository %s (no branches or branches point to empty commits)", coreRepo.Root)
		return nil
	}

	head := 0
	for head < len(queue) {
		commitHash := queue[head]
		head++

		// Check if commit already exists in DB
		_, dbErr := sm.commitService.GetCommitByHash(repoModel.ID, commitHash)
		if dbErr == nil {
			// Commit already in DB. We assume its parents are also processed or will be.
			continue
		}
		if !errors.Is(dbErr, gorm.ErrRecordNotFound) { // Actual error other than not found
			return fmt.Errorf("error checking commit %s in DB: %w", commitHash, dbErr)
		}

		// Commit not in DB, fetch and parse it
		coreCommit, err := coreRepo.GetCommit(commitHash) // Use coreRepo.GetCommit now
		if err != nil {
			// Check if it's a "not found" error from the core, which might be acceptable if a ref pointed to a non-existent commit
			if core.IsErrNotFound(err) { // Assuming core.IsErrNotFound exists and works for GetCommit
				sm.manager.logger.Printf("Warning: Commit object %s not found in core repository %s: %v", commitHash, coreRepo.Root, err)
			} else {
				sm.manager.logger.Printf("Error: Failed to get commit object %s from %s: %v", commitHash, coreRepo.Root, err)
			}
			continue // Or handle error more strictly
		}

		parsedCommit, err := adaptCoreCommit(coreCommit)
		if err != nil {
			sm.manager.logger.Printf("Error: Failed to adapt core commit data for %s: %v", commitHash, err)
			continue
		}

		// Create models.Commit struct
		newDbCommit := &models.Commit{
			RepositoryID:   repoModel.ID,
			CommitID:       parsedCommit.Hash, // This is coreCommit.CommitID
			TreeHash:       parsedCommit.TreeHash,
			AuthorName:     parsedCommit.AuthorName,
			AuthorEmail:    parsedCommit.AuthorEmail,
			AuthoredAt:     parsedCommit.AuthoredAt,
			CommitterName:  parsedCommit.CommitterName,
			CommitterEmail: parsedCommit.CommitterEmail,
			CommittedAt:    parsedCommit.CommittedAt,
			Message:        parsedCommit.Message,
		}

		if err := sm.commitService.CreateCommit(newDbCommit); err != nil {
			// Handle potential race condition if another process synced this commit meanwhile
			if !strings.Contains(err.Error(), "UNIQUE constraint failed") && !strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
				return fmt.Errorf("failed to create commit %s in DB: %w", newDbCommit.CommitID, err)
			}
			// If it was a unique constraint error, the commit was just created. Fetch it to add parents.
			existingCommit, getErr := sm.commitService.GetCommitByHash(repoModel.ID, newDbCommit.CommitID)
			if getErr != nil {
				return fmt.Errorf("failed to fetch concurrently created commit %s: %w", newDbCommit.CommitID, getErr)
			}
			newDbCommit = existingCommit // Use the one from DB for parent linking
		}

		// Process parents
		for _, parentHash := range parsedCommit.ParentHashes { // These are from coreCommit.Parents
			// Ensure parent exists in DB or will be processed
			parentDbCommit, parentErr := sm.commitService.GetCommitByHash(repoModel.ID, parentHash)
			if parentErr != nil {
				if errors.Is(parentErr, gorm.ErrRecordNotFound) {
					// Parent not yet in DB, add to queue if not visited
					if !visited[parentHash] {
						queue = append(queue, parentHash)
						visited[parentHash] = true
					}
				} else {
					return fmt.Errorf("error fetching parent commit %s for DB link: %w", parentHash, parentErr)
				}
			} else { // Parent is in DB
				// Check if already linked to prevent duplicate entries if relationship table has unique constraint
				// This check depends on how GORM handles AddCommitParent and if it's idempotent
				// For now, we assume AddCommitParent handles duplicates gracefully or the DB schema allows multiple links (less likely)
				if err := sm.commitService.AddCommitParent(newDbCommit, parentDbCommit); err != nil {
					sm.manager.logger.Printf("Warning: failed to link parent %s to commit %s: %v", parentHash, newDbCommit.CommitID, err)
				}
			}

			// Also add unvisited parents to queue for processing their details
			// This was slightly redundant as the check for GORM not found above already adds to queue.
			// Keeping it here ensures that if parentDbCommit was found, but for some reason we still want to re-queue it
			// (e.g. to update something on it - though current logic doesn't do that), it would be added.
			// For current logic, it's fine.
			if !visited[parentHash] { // This condition will likely be false if parentErr was gorm.ErrRecordNotFound
				queue = append(queue, parentHash)
				visited[parentHash] = true
			}
		}
	}
	return nil
}

// Removed old parseCoreCommitData and signature struct as they are no longer used.
// The new adaptCoreCommit and parseGitStyleSignature handle the conversion from core.Commit.
