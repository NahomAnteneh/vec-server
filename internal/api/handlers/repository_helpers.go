package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

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
		// Log or handle missing permissionService appropriately
		return false
	}

	hasAccess, _ := permService.HasPermission(user.ID, repo.ID, models.ReadPermission)
	return hasAccess
}

// isValidCommitHash checks if a string is a valid commit hash (SHA256, 64 hex chars)
func isValidCommitHash(hash string) bool {
	if len(hash) != 64 { // SHA256 is 64 hex characters
		return false
	}

	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}

// getAuthorParts splits an author string (e.g., "Name <email@example.com>") into name and email.
func getAuthorParts(authorStr string) (name, email string) {
	parts := strings.SplitN(authorStr, " <", 2)
	name = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		email = strings.TrimSuffix(strings.TrimSpace(parts[1]), ">")
	} else {
		// Handle cases where email might be missing or format is different
		// For now, if no " <", assume the whole string is the name
	}
	return
}

// getCommitDetails retrieves details about a commit using the core library.
// It converts a core.Commit object into a CommitResponse suitable for API responses.
func getCommitDetails(repoPath, commitHash string) (*CommitResponse, error) {
	coreCommit, err := core.GetCommit(repoPath, commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get core commit %s: %w", commitHash, err)
	}

	authorName, authorEmail := getAuthorParts(coreCommit.Author)
	committerName, committerEmail := getAuthorParts(coreCommit.Committer)

	// core.Commit.Timestamp is already a time.Time object
	authorDate := coreCommit.Timestamp
	commitDate := coreCommit.Timestamp // Using the single timestamp from core.Commit for both

	return &CommitResponse{
		Hash:           coreCommit.CommitID,
		TreeHash:       coreCommit.Tree,
		Author:         authorName,
		AuthorEmail:    authorEmail,
		CommitterName:  committerName,
		CommitterEmail: committerEmail,
		Message:        coreCommit.Message,
		ShortMessage:   getShortMessage(coreCommit.Message),
		ParentHashes:   coreCommit.Parents,
		CommitDate:     commitDate,
		AuthorDate:     authorDate,
	}, nil
}

// getShortMessage returns the first line of a commit message.
func getShortMessage(message string) string {
	lines := strings.SplitN(message, "\n", 2)
	if len(lines) > 0 {
		return lines[0]
	}
	return message
}

// getTreeEntries retrieves entries in a tree using the core library.
// It converts core.TreeEntry objects into TreeEntryResponse suitable for API responses.
func getTreeEntries(repoPath, treeHash string) ([]TreeEntryResponse, error) {
	coreTree, err := core.GetTree(repoPath, treeHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get core tree %s: %w", treeHash, err)
	}

	entries := make([]TreeEntryResponse, 0, len(coreTree.Entries))
	for _, coreEntry := range coreTree.Entries {
		// Format mode as 6-digit octal, common in Git (e.g., 100644, 040000)
		modeStr := fmt.Sprintf("%06o", coreEntry.Mode)

		entries = append(entries, TreeEntryResponse{
			Name: coreEntry.Name,
			Path: coreEntry.Name, // Path here is relative to the current tree. Full path needs to be constructed by caller if browsing subdirectories.
			Type: coreEntry.Type, // "blob" or "tree"
			Mode: modeStr,
			Hash: coreEntry.Hash,
			// Size is not part of a standard Git tree entry; it's derived from the blob object itself.
			// Omitting Size for TreeEntryResponse as per original logic. If needed, it would require fetching each blob.
		})
	}

	return entries, nil
}

// getBlobContent retrieves the content of a blob object.
func getBlobContent(repoPath, blobHash string) (string, []byte, bool, error) {
	cr := core.NewRepository(repoPath)                  // Create core.Repository instance
	objType, data, err := core.ReadObject(cr, blobHash) // Use core.ReadObject with *core.Repository
	if err != nil {
		return "", nil, false, fmt.Errorf("failed to read blob %s: %w", blobHash, err)
	}
	if objType != "blob" {
		return "", nil, false, fmt.Errorf("object %s is not a blob, but a %s", blobHash, objType)
	}

	// Basic check for binary content (e.g., presence of null bytes)
	// This is a simple heuristic and might not be exhaustive.
	isBinary := false
	for _, b := range data {
		if b == 0 {
			isBinary = true
			break
		}
	}
	return objType, data, isBinary, nil
}
