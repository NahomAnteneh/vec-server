package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// CommitResponse represents a commit in the API response
type CommitResponse struct {
	Hash           string    `json:"hash"`
	Author         string    `json:"author"`
	AuthorEmail    string    `json:"author_email"`
	CommitterName  string    `json:"committer_name,omitempty"`
	CommitterEmail string    `json:"committer_email,omitempty"`
	Message        string    `json:"message"`
	ShortMessage   string    `json:"short_message"`
	ParentHashes   []string  `json:"parent_hashes"`
	CommitDate     time.Time `json:"commit_date"`
	AuthorDate     time.Time `json:"author_date"`
}

// BranchResponse represents a branch in the API response
type BranchResponse struct {
	Name       string          `json:"name"`
	Target     string          `json:"target"`
	IsHead     bool            `json:"is_head"`
	LastCommit *CommitResponse `json:"last_commit,omitempty"`
}

// TreeEntryResponse represents an entry in a tree
type TreeEntryResponse struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // "blob" or "tree"
	Mode string `json:"mode"`
	Size int64  `json:"size,omitempty"`
	Hash string `json:"hash"`
}

// FileContentResponse represents a file content response
type FileContentResponse struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int    `json:"size"`
	Hash    string `json:"hash"`
	Binary  bool   `json:"binary"`
}

// ListBranches returns a list of all branches in the repository
func ListBranches(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		refs, err := repoManager.GetRefs(repo)
		if err != nil {
			http.Error(w, "Failed to list branches: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get current branch
		headRef, err := repoManager.GetRef(repo, "HEAD")
		if err != nil {
			http.Error(w, "Failed to get HEAD reference: "+err.Error(), http.StatusInternalServerError)
			return
		}

		headBranch := ""
		if headRef != nil && strings.HasPrefix(headRef.Value, "ref: refs/heads/") {
			headBranch = strings.TrimPrefix(headRef.Value, "ref: refs/heads/")
		}

		branches := make([]BranchResponse, 0)
		for refName, target := range refs {
			if strings.HasPrefix(refName, "refs/heads/") {
				branchName := strings.TrimPrefix(refName, "refs/heads/")
				branch := BranchResponse{
					Name:   branchName,
					Target: target,
					IsHead: branchName == headBranch,
				}
				branches = append(branches, branch)
			}
		}

		render.JSON(w, r, map[string]interface{}{
			"branches": branches,
			"count":    len(branches),
		})
	}
}

// GetBranch returns details about a specific branch
func GetBranch(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		branchName := chi.URLParam(r, "branch")
		if branchName == "" {
			http.Error(w, "Branch name is required", http.StatusBadRequest)
			return
		}

		refName := "refs/heads/" + branchName
		ref, err := repoManager.GetRef(repo, refName)
		if err != nil {
			http.Error(w, "Branch not found: "+err.Error(), http.StatusNotFound)
			return
		}

		headRef, _ := repoManager.GetRef(repo, "HEAD")
		isHead := false
		if headRef != nil && strings.HasPrefix(headRef.Value, "ref: refs/heads/") {
			headBranch := strings.TrimPrefix(headRef.Value, "ref: refs/heads/")
			isHead = headBranch == branchName
		}

		commitHash := ref.Value
		commit, err := getCommitDetails(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Failed to get commit details: "+err.Error(), http.StatusInternalServerError)
			return
		}

		branch := BranchResponse{
			Name:       branchName,
			Target:     commitHash,
			IsHead:     isHead,
			LastCommit: commit,
		}

		render.JSON(w, r, branch)
	}
}

// ListCommits returns a list of commits in the repository
func ListCommits(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		refName := r.URL.Query().Get("ref")
		if refName == "" {
			// Default to HEAD
			headRef, err := repoManager.GetRef(repo, "HEAD")
			if err == nil && headRef != nil {
				if strings.HasPrefix(headRef.Value, "ref: ") {
					refName = strings.TrimPrefix(headRef.Value, "ref: ")
				} else {
					refName = "HEAD"
				}
			} else {
				refName = "HEAD"
			}
		}

		limit := 20
		if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
			if parsedLimit, err := strconv.Atoi(limitParam); err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}

		page := 1
		if pageParam := r.URL.Query().Get("page"); pageParam != "" {
			if parsedPage, err := strconv.Atoi(pageParam); err == nil && parsedPage > 0 {
				page = parsedPage
			}
		}

		// TODO: Implement proper commit listing with pagination
		// This is a placeholder until we implement proper commit traversal
		commits := make([]*CommitResponse, 0)

		refObj, err := repoManager.GetRef(repo, refName)
		if err != nil || refObj == nil {
			// If refName is not a ref, try it directly as a commit hash
			commit, err := getCommitDetails(repo.Path, refName)
			if err != nil {
				http.Error(w, "Reference not found: "+err.Error(), http.StatusNotFound)
				return
			}
			commits = append(commits, commit)
		} else {
			// Get commit from ref
			commitHash := refObj.Value
			commit, err := getCommitDetails(repo.Path, commitHash)
			if err != nil {
				http.Error(w, "Failed to get commit details: "+err.Error(), http.StatusInternalServerError)
				return
			}
			commits = append(commits, commit)

			// Add parent commits if available
			for i := 0; i < limit-1 && i < len(commits); i++ {
				for _, parentHash := range commits[i].ParentHashes {
					parentCommit, err := getCommitDetails(repo.Path, parentHash)
					if err == nil {
						commits = append(commits, parentCommit)
						if len(commits) >= limit {
							break
						}
					}
				}
				if len(commits) >= limit {
					break
				}
			}
		}

		render.JSON(w, r, map[string]interface{}{
			"commits": commits,
			"count":   len(commits),
			"page":    page,
			"limit":   limit,
		})
	}
}

// GetCommit returns details about a specific commit
func GetCommit(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		commitHash := chi.URLParam(r, "commit")
		if commitHash == "" {
			http.Error(w, "Commit hash is required", http.StatusBadRequest)
			return
		}

		commit, err := getCommitDetails(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Commit not found: "+err.Error(), http.StatusNotFound)
			return
		}

		render.JSON(w, r, commit)
	}
}

// GetTreeContents returns the contents of a tree
func GetTreeContents(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ref := chi.URLParam(r, "ref")
		if ref == "" {
			http.Error(w, "Reference is required", http.StatusBadRequest)
			return
		}

		path := chi.URLParam(r, "path")

		// Get commit hash from ref
		commitHash := ref
		if !isValidCommitHash(ref) {
			refObj, err := repoManager.GetRef(repo, "refs/heads/"+ref)
			if err != nil {
				// Try other refs
				refObj, err = repoManager.GetRef(repo, ref)
				if err != nil {
					http.Error(w, "Reference not found: "+err.Error(), http.StatusNotFound)
					return
				}
			}
			commitHash = refObj.Value
		}

		// Get tree from commit
		commit, err := core.GetCommit(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Invalid commit reference", http.StatusBadRequest)
			return
		}

		treeHash := commit.Tree

		// If path is specified, navigate to that directory
		if path != "" {
			treeEntries, err := getTreeEntries(repo.Path, treeHash)
			if err != nil {
				http.Error(w, "Failed to read tree: "+err.Error(), http.StatusInternalServerError)
				return
			}

			pathParts := strings.Split(path, "/")
			for i, part := range pathParts {
				found := false
				for _, entry := range treeEntries {
					if entry.Name == part && entry.Type == "tree" {
						treeHash = entry.Hash
						found = true

						if i < len(pathParts)-1 {
							treeEntries, err = getTreeEntries(repo.Path, entry.Hash)
							if err != nil {
								http.Error(w, "Failed to read subtree: "+err.Error(), http.StatusInternalServerError)
								return
							}
						}
						break
					}
				}

				if !found {
					http.Error(w, "Path not found: "+path, http.StatusNotFound)
					return
				}
			}
		}

		entries, err := getTreeEntries(repo.Path, treeHash)
		if err != nil {
			http.Error(w, "Failed to read tree: "+err.Error(), http.StatusInternalServerError)
			return
		}

		render.JSON(w, r, map[string]interface{}{
			"entries":     entries,
			"count":       len(entries),
			"commit_hash": commitHash,
			"tree_hash":   treeHash,
			"path":        path,
		})
	}
}

// GetBlob returns the contents of a blob
func GetBlob(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoCtx := getRepositoryContext(r)
		if repoCtx == nil {
			http.Error(w, "Repository context not found", http.StatusInternalServerError)
			return
		}

		repo := repoCtx.Repository
		if !canAccessRepository(r, repo) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ref := chi.URLParam(r, "ref")
		if ref == "" {
			http.Error(w, "Reference is required", http.StatusBadRequest)
			return
		}

		path := chi.URLParam(r, "path")
		if path == "" {
			http.Error(w, "File path is required", http.StatusBadRequest)
			return
		}

		// Get commit hash from ref
		commitHash := ref
		if !isValidCommitHash(ref) {
			refObj, err := repoManager.GetRef(repo, "refs/heads/"+ref)
			if err != nil {
				// Try other refs
				refObj, err = repoManager.GetRef(repo, ref)
				if err != nil {
					http.Error(w, "Reference not found: "+err.Error(), http.StatusNotFound)
					return
				}
			}
			commitHash = refObj.Value
		}

		// Get tree from commit
		commit, err := core.GetCommit(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Invalid commit reference", http.StatusBadRequest)
			return
		}

		treeHash := commit.Tree

		// Navigate to the file
		pathParts := strings.Split(path, "/")
		fileName := pathParts[len(pathParts)-1]
		dirPath := strings.Join(pathParts[:len(pathParts)-1], "/")

		// Navigate through directories if needed
		if dirPath != "" {
			dirParts := strings.Split(dirPath, "/")
			currentTreeHash := treeHash

			for _, part := range dirParts {
				entries, err := getTreeEntries(repo.Path, currentTreeHash)
				if err != nil {
					http.Error(w, "Failed to read tree: "+err.Error(), http.StatusInternalServerError)
					return
				}

				found := false
				for _, entry := range entries {
					if entry.Name == part && entry.Type == "tree" {
						currentTreeHash = entry.Hash
						found = true
						break
					}
				}

				if !found {
					http.Error(w, "Directory not found: "+dirPath, http.StatusNotFound)
					return
				}
			}

			treeHash = currentTreeHash
		}

		// Find the file in the tree
		entries, err := getTreeEntries(repo.Path, treeHash)
		if err != nil {
			http.Error(w, "Failed to read tree: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var fileHash string
		fileFound := false
		for _, entry := range entries {
			if entry.Name == fileName && entry.Type == "blob" {
				fileHash = entry.Hash
				fileFound = true
				break
			}
		}

		if !fileFound {
			http.Error(w, "File not found: "+fileName, http.StatusNotFound)
			return
		}

		// Read blob content
		content, err := core.GetBlob(repo.Path, fileHash)
		if err != nil {
			http.Error(w, "Failed to read file content: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if content is binary
		isBinary := false
		for _, b := range content {
			if b == 0 {
				isBinary = true
				break
			}
		}

		response := FileContentResponse{
			Name:   fileName,
			Path:   path,
			Hash:   fileHash,
			Size:   len(content),
			Binary: isBinary,
		}

		if !isBinary {
			response.Content = string(content)
		} else {
			// For binary content, return base64 or handle appropriately
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
			w.Write(content)
			return
		}

		render.JSON(w, r, response)
	}
}

// Helper functions

// getRepositoryContext retrieves repository context from the request
func getRepositoryContext(r *http.Request) *middleware.RepositoryContext {
	repoCtx, ok := r.Context().Value(middleware.RepositoryContextKey).(*middleware.RepositoryContext)
	if !ok || repoCtx == nil {
		return nil
	}
	return repoCtx
}

// canAccessRepository checks if the user can access the repository
func canAccessRepository(r *http.Request, repo *models.Repository) bool {
	if repo.IsPublic {
		return true
	}

	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		return false
	}

	if user.ID == repo.OwnerID {
		return true
	}

	permService, ok := r.Context().Value("permissionService").(models.PermissionService)
	if !ok {
		return false
	}

	hasAccess, _ := permService.HasPermission(user.ID, repo.ID, models.ReadPermission)
	return hasAccess
}

// isValidCommitHash checks if a string is a valid commit hash
func isValidCommitHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}

	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}

// getAuthorParts splits an author string into name and email
func getAuthorParts(authorStr string) (name, email string) {
	parts := strings.Split(authorStr, " <")
	if len(parts) < 2 {
		return authorStr, ""
	}

	name = parts[0]
	email = strings.TrimSuffix(parts[1], ">")
	return
}

// getCommitTime parses a timestamp into a time
func getCommitTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}

// getCommitDetails retrieves details about a commit
func getCommitDetails(repoPath, commitHash string) (*CommitResponse, error) {
	commit, err := core.GetCommit(repoPath, commitHash)
	if err != nil {
		return nil, err
	}

	authorName, authorEmail := getAuthorParts(commit.Author)
	committerName, committerEmail := getAuthorParts(commit.Committer)

	return &CommitResponse{
		Hash:           commitHash,
		Author:         authorName,
		AuthorEmail:    authorEmail,
		CommitterName:  committerName,
		CommitterEmail: committerEmail,
		Message:        commit.Message,
		ShortMessage:   getShortMessage(commit.Message),
		ParentHashes:   commit.Parents,
		CommitDate:     getCommitTime(commit.Timestamp),
		AuthorDate:     getCommitTime(commit.Timestamp), // Using same timestamp for author/commit dates
	}, nil
}

// getShortMessage returns the first line of a commit message
func getShortMessage(message string) string {
	lines := strings.Split(message, "\n")
	if len(lines) > 0 {
		return lines[0]
	}
	return message
}

// getTreeEntries retrieves entries in a tree
func getTreeEntries(repoPath, treeHash string) ([]TreeEntryResponse, error) {
	tree, err := core.GetTree(repoPath, treeHash)
	if err != nil {
		return nil, err
	}

	entries := make([]TreeEntryResponse, 0, len(tree.Entries))
	for _, entry := range tree.Entries {
		modeStr := fmt.Sprintf("%o", entry.Mode)

		entries = append(entries, TreeEntryResponse{
			Name: entry.Name,
			Path: entry.Name,
			Type: entry.Type,
			Mode: modeStr,
			Hash: entry.Hash,
		})
	}

	return entries, nil
}
