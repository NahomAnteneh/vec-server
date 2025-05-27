package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// CommitResponse represents a commit in the API response
type CommitResponse struct {
	Hash           string    `json:"hash"`
	TreeHash       string    `json:"tree_hash,omitempty"`
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
func ListBranches() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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

		// Initialize headCommitHash before use
		var headCommitHash string
		headCommitHash, err := repoManager.GetHeadCommitHash(repo.Path)
		if err != nil {
			// Log error, but proceed. HEAD might be unresolvable in some states (e.g. empty repo before first commit)
			// Consider if this should be a hard error.
			// For now, if HEAD is unresolvable, no branch will be marked as IsHead unless it matches a symbolic ref to a known branch head.
			if headCommitHash == "" && err != nil { // If GetHeadCommitHash failed, ensure headCommitHash is explicitly empty for logic below
				headCommitHash = "" // or some other indicator that it's unresolved
			}
		}

		// Determine the current symbolic HEAD target (e.g. "refs/heads/main")
		cr := core.NewRepository(repo.Path)         // Create core.Repository instance
		symbolicHeadRef, _ := core.ReadHEADFile(cr) // Ignores error, if HEAD is detached or invalid, headBranch remains empty
		headBranchName := ""
		if strings.HasPrefix(symbolicHeadRef, "ref: refs/heads/") {
			headBranchName = strings.TrimPrefix(symbolicHeadRef, "ref: refs/heads/")
		}

		branchMap, branchErr := repoManager.GetBranches(repo.Path)
		if branchErr != nil {
			http.Error(w, "Failed to list branches: "+branchErr.Error(), http.StatusInternalServerError)
			return
		}

		branches := make([]BranchResponse, 0, len(branchMap))
		for name, commitHash := range branchMap {
			commitDetails, err := getCommitDetails(repo.Path, commitHash) // Fetch commit details for LastCommit
			if err != nil {
				// Log this error but continue, or skip this branch in the response
				// For now, we'll add the branch without commit details if this fails.
				commitDetails = nil // Or a new empty CommitResponse
			}

			branch := BranchResponse{
				Name:       name,
				Target:     commitHash,
				IsHead:     (name == headBranchName) || (commitHash == headCommitHash && headBranchName == ""), // Branch is HEAD if its name matches symbolic HEAD, or if its commit matches detached HEAD's commit and no symbolic HEAD branch
				LastCommit: commitDetails,
			}
			branches = append(branches, branch)
		}

		render.JSON(w, r, map[string]interface{}{
			"branches": branches,
			"count":    len(branches),
		})
	}
}

// GetBranch returns details about a specific branch
func GetBranch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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

		commitHash, err := repoManager.GetCommitForBranch(repo.Path, branchName)
		if err != nil {
			http.Error(w, "Branch not found: "+err.Error(), http.StatusNotFound)
			return
		}

		actualHeadCommitHash, _ := repoManager.GetHeadCommitHash(repo.Path)
		// core.ReadHEADFile now expects *core.Repository
		cr := core.NewRepository(repo.Path) // Create core.Repository instance
		symbolicHeadRef, _ := core.ReadHEADFile(cr)
		isHead := false
		if strings.HasPrefix(symbolicHeadRef, "ref: refs/heads/") {
			isHead = (strings.TrimPrefix(symbolicHeadRef, "ref: refs/heads/") == branchName)
		} else if symbolicHeadRef == commitHash { // Detached HEAD (symbolicHeadRef is a commit hash)
			isHead = true
		} else if actualHeadCommitHash == commitHash && !strings.HasPrefix(symbolicHeadRef, "ref: refs/heads/") {
			// Covers cases where HEAD is detached and points to the current branch's commit,
			// and symbolicHeadRef itself wasn't a direct hash match to commitHash (already covered).
			isHead = true
		}

		commitDetails, detailsErr := getCommitDetails(repo.Path, commitHash)
		if detailsErr != nil {
			http.Error(w, "Failed to get commit details: "+detailsErr.Error(), http.StatusInternalServerError)
			return
		}

		branch := BranchResponse{
			Name:       branchName,
			Target:     commitHash,
			IsHead:     isHead,
			LastCommit: commitDetails,
		}

		render.JSON(w, r, branch)
	}
}

// ListCommits returns a list of commits in the repository
func ListCommits() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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

		branchService, ok := r.Context().Value("branchService").(models.BranchService)
		if !ok {
			http.Error(w, "Branch service not found", http.StatusInternalServerError)
			return
		}

		refName := r.URL.Query().Get("ref") // Can be branch name, commit hash, or empty (defaults to HEAD)
		startCommitHash := ""

		if refName == "" || refName == "HEAD" {
			// Try to get default branch's head commit from DB first
			dbDefaultBranch, err := branchService.GetDefaultBranch(repo.ID)
			if err == nil && dbDefaultBranch != nil {
				startCommitHash = dbDefaultBranch.CommitID
			} else {
				// Fallback to repoManager for HEAD if not in DB or no default branch
				fsHeadCommit, errFs := repoManager.GetHeadCommitHash(repo.Path)
				if errFs == nil && fsHeadCommit != "" {
					startCommitHash = fsHeadCommit
				} else {
					http.Error(w, "Failed to determine starting commit for HEAD", http.StatusNotFound)
					return
				}
			}
		} else if isValidCommitHash(refName) { // Direct commit hash
			startCommitHash = refName
		} else {
			// Assume refName is a branch name
			dbBranch, err := branchService.GetByName(repo.ID, refName)
			if err == nil && dbBranch != nil {
				startCommitHash = dbBranch.CommitID
			} else {
				// Fallback: check filesystem for branch if not in DB (though it should be if synced)
				fsBranchCommit, errFs := repoManager.GetCommitForBranch(repo.Path, refName)
				if errFs == nil && fsBranchCommit != "" {
					startCommitHash = fsBranchCommit
				} else {
					http.Error(w, fmt.Sprintf("Ref '%s' not found", refName), http.StatusNotFound)
					return
				}
			}
		}

		if startCommitHash == "" {
			http.Error(w, "Could not determine starting commit for listing.", http.StatusInternalServerError)
			return
		}

		// Pagination parameters
		limitStr := r.URL.Query().Get("limit")
		limit := 20 // Default limit
		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				if l > 100 { // Max limit
					l = 100
				}
				limit = l
			}
		}

		// Use core.FindReachableObjects to get commit history hashes
		cr := core.NewRepository(repo.Path)
		// core.FindReachableObjects now returns []string (hashes) and takes only repo and startCommitHash
		commitHashes, err := core.FindReachableObjects(cr, startCommitHash)
		if err != nil {
			// Check if the error is because the startCommitHash was not found in core
			if core.IsErrNotFound(err) {
				http.Error(w, fmt.Sprintf("Commit '%s' not found in repository history", startCommitHash), http.StatusNotFound)
			} else {
				http.Error(w, "Failed to retrieve commits: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		commitResponses := make([]CommitResponse, 0, len(commitHashes))
		// Apply limit after fetching all reachable, or modify FindReachableObjects if it can support limit
		numToProcess := len(commitHashes)
		if limit < numToProcess {
			numToProcess = limit
		}

		for i := 0; i < numToProcess; i++ {
			commitHash := commitHashes[i]
			// Convert core.Commit (obtained via getCommitDetails) to CommitResponse
			// getCommitDetails already handles calling core.GetCommit(repo.Path, commitHash)
			commitDetail, err := getCommitDetails(repo.Path, commitHash)
			if err != nil {
				// Log error and potentially skip this commit in the response
				// Placeholder for logging: log.Printf("Error getting details for commit %s: %v", commitHash, err)
				continue
			}
			commitResponses = append(commitResponses, *commitDetail) // commitDetail is already a *CommitResponse
		}

		render.JSON(w, r, map[string]interface{}{
			"commits": commitResponses,
			"count":   len(commitResponses),
			// TODO: Add pagination info (next_cursor, etc.) if FindReachableObjects supports it
		})
	}
}

// GetCommit returns details about a specific commit
func GetCommit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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
func GetTreeContents() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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
			// Default to HEAD if ref is not provided
			ref = "HEAD"
		}

		path := chi.URLParam(r, "path")

		var commitHash string
		var err error

		// Resolve ref to a commit hash
		if isValidCommitHash(ref) {
			commitHash = ref
		} else if ref == "HEAD" {
			commitHash, err = repoManager.GetHeadCommitHash(repo.Path)
			if err != nil {
				http.Error(w, "Failed to resolve HEAD: "+err.Error(), http.StatusNotFound)
				return
			}
		} else {
			// Try as a branch name using BranchService first
			branchService, ok := r.Context().Value("branchService").(models.BranchService)
			if !ok {
				http.Error(w, "Branch service not found", http.StatusInternalServerError)
				return
			}
			dbBranch, dbErr := branchService.GetByName(repo.ID, ref)
			if dbErr == nil && dbBranch != nil {
				commitHash = dbBranch.CommitID
			} else {
				// Fallback to repoManager for branch lookup if not in DB or error
				commitHash, err = repoManager.GetCommitForBranch(repo.Path, ref)
				if err != nil {
					http.Error(w, fmt.Sprintf("Reference '%s' not found: %s", ref, err.Error()), http.StatusNotFound)
					return
				}
			}
		}

		if commitHash == "" {
			http.Error(w, "Could not resolve reference to a commit", http.StatusInternalServerError)
			return
		}

		// Get tree from commit
		commitDetails, err := getCommitDetails(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Invalid commit reference: "+err.Error(), http.StatusBadRequest)
			return
		}

		treeHash := commitDetails.TreeHash // Use TreeHash from parsed commit details

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

// GetBlob returns the content of a blob (file)
func GetBlob() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok || repoManager == nil {
			http.Error(w, "Repository manager not found in context", http.StatusInternalServerError)
			return
		}
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

		refParam := chi.URLParam(r, "ref") // Changed from "ref" to "refParam" to avoid conflict
		if refParam == "" {
			refParam = "HEAD" // Default to HEAD
		}
		filePath := chi.URLParam(r, "path") // Changed from "path" to "filePath"
		if filePath == "" {
			http.Error(w, "File path is required", http.StatusBadRequest)
			return
		}

		var commitHash string
		var err error

		// 1. Resolve refParam to a commitHash
		if isValidCommitHash(refParam) {
			commitHash = refParam
		} else if refParam == "HEAD" {
			commitHash, err = repoManager.GetHeadCommitHash(repo.Path)
			if err != nil {
				http.Error(w, "Failed to resolve HEAD: "+err.Error(), http.StatusNotFound)
				return
			}
		} else {
			branchService, ok := r.Context().Value("branchService").(models.BranchService)
			if !ok {
				http.Error(w, "Branch service not found", http.StatusInternalServerError)
				return
			}
			dbBranch, dbErr := branchService.GetByName(repo.ID, refParam)
			if dbErr == nil && dbBranch != nil {
				commitHash = dbBranch.CommitID
			} else {
				commitHash, err = repoManager.GetCommitForBranch(repo.Path, refParam)
				if err != nil {
					http.Error(w, fmt.Sprintf("Reference '%s' not found: %s", refParam, err.Error()), http.StatusNotFound)
					return
				}
			}
		}
		if commitHash == "" {
			http.Error(w, "Could not resolve reference to a commit", http.StatusInternalServerError)
			return
		}

		// 2. Get root treeHash from commit
		commitDetails, err := getCommitDetails(repo.Path, commitHash)
		if err != nil {
			http.Error(w, "Failed to get commit details: "+err.Error(), http.StatusInternalServerError)
			return
		}
		currentTreeHash := commitDetails.TreeHash

		// 3. Traverse filePath to find blob hash
		pathParts := strings.Split(strings.Trim(filePath, "/"), "/")
		var blobHash string
		fileName := pathParts[len(pathParts)-1]

		for i, partName := range pathParts {
			treeEntries, err := getTreeEntries(repo.Path, currentTreeHash)
			if err != nil {
				http.Error(w, "Failed to read tree contents: "+err.Error(), http.StatusInternalServerError)
				return
			}
			foundEntry := false
			for _, entry := range treeEntries {
				if entry.Name == partName {
					if i == len(pathParts)-1 { // Last part of the path
						if entry.Type == "blob" {
							blobHash = entry.Hash
						} else {
							http.Error(w, fmt.Sprintf("Path '%s' is a directory, not a file", filePath), http.StatusBadRequest)
							return
						}
					} else { // Intermediate part of the path
						if entry.Type == "tree" {
							currentTreeHash = entry.Hash
						} else {
							http.Error(w, fmt.Sprintf("Path component '%s' in '%s' is not a directory", partName, filePath), http.StatusBadRequest)
							return
						}
					}
					foundEntry = true
					break
				}
			}
			if !foundEntry {
				http.Error(w, fmt.Sprintf("Path '%s' not found in repository", filePath), http.StatusNotFound)
				return
			}
		}

		if blobHash == "" {
			http.Error(w, fmt.Sprintf("File '%s' not found at the specified path", filePath), http.StatusNotFound)
			return
		}

		// 4. Read blob content using core.ReadObject
		cr := core.NewRepository(repo.Path)                         // Create a core.Repository instance
		objType, contentBytes, err := core.ReadObject(cr, blobHash) // Pass 'cr'
		if err != nil {
			http.Error(w, "Failed to read file content: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if objType != "blob" {
			http.Error(w, "Expected a blob object but found "+objType, http.StatusInternalServerError)
			return
		}

		// Existing binary detection and response logic
		isBinary := false
		for _, b := range contentBytes {
			if b == 0 {
				isBinary = true
				break
			}
		}

		response := FileContentResponse{
			Name:   fileName,
			Path:   filePath,
			Hash:   blobHash,
			Size:   len(contentBytes),
			Binary: isBinary,
		}

		if !isBinary {
			response.Content = string(contentBytes)
			render.JSON(w, r, response)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
			w.Write(contentBytes)
		}
	}
}
