package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	// Required for ForkRepository, UpdateRepository (indirectly via helpers if they were here)
	// Required for getRepositoryContext if used directly, not here
	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// RepoResponse represents the response format for repository operations
type RepoResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	OwnerID     uint   `json:"owner_id"`
	Description string `json:"description,omitempty"`
	Private     bool   `json:"private"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// RepoRequest represents the request format for repository creation/update
type RepoRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Private     bool   `json:"private"`
}

// CreateRepository handles the creation of a new repository
func CreateRepository(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req RepoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "Repository name is required", http.StatusBadRequest)
			return
		}

		repo := &models.Repository{
			Name:     req.Name,
			OwnerID:  user.ID,
			IsPublic: !req.Private,
		}

		if err := repoService.Create(repo); err != nil {
			http.Error(w, "Failed to create repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the repository manager from context and create the repository on disk
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok {
			http.Error(w, "Repository manager not found", http.StatusInternalServerError)
			return
		}

		// Create the repository path and structure on disk
		if _, err := repoManager.CreateRepo(user.Username, repo.Name); err != nil {
			http.Error(w, "Failed to create repository files: "+err.Error(), http.StatusInternalServerError)
			return
		}

		render.Status(r, http.StatusCreated)
		render.JSON(w, r, RepoResponse{
			ID:        repo.ID,
			Name:      repo.Name,
			Owner:     user.Username,
			OwnerID:   user.ID,
			Private:   !repo.IsPublic,
			CreatedAt: repo.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// GetRepository retrieves repository metadata
func GetRepository(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoName := chi.URLParam(r, "repo")
		username := chi.URLParam(r, "username")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if !repo.IsPublic {
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if user.ID != repo.OwnerID {
				// This needs canAccessRepository or direct permission check
				// For now, assuming direct check as helper is not yet moved.
				permService, ok := r.Context().Value("permissionService").(models.PermissionService)
				if !ok {
					http.Error(w, "Permission service not found", http.StatusInternalServerError)
					return
				}
				hasAccess, _ := permService.HasPermission(user.ID, repo.ID, models.ReadPermission)
				if !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		render.JSON(w, r, RepoResponse{
			ID:        repo.ID,
			Name:      repo.Name,
			Owner:     repo.Owner.Username,
			OwnerID:   repo.OwnerID,
			Private:   !repo.IsPublic,
			CreatedAt: repo.CreatedAt.Format(http.TimeFormat),
			UpdatedAt: repo.UpdatedAt.Format(http.TimeFormat),
		})
	}
}

// UpdateRepository updates repository settings
func UpdateRepository(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		repoName := chi.URLParam(r, "repo")
		username := chi.URLParam(r, "username")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if user.ID != repo.OwnerID {
			permService := r.Context().Value("permissionService").(models.PermissionService)
			if permService == nil {
				http.Error(w, "Permission service not found", http.StatusInternalServerError)
				return
			}
			hasAdmin, _ := permService.HasPermission(user.ID, repo.ID, models.AdminPermission)
			if !hasAdmin {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		var req RepoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if req.Name != "" && req.Name != repo.Name {
			// TODO: Add logic to rename repository on disk using repoManager
			// oldPath, _ := repoManager.GetRepoPath(username, repo.Name)
			repo.Name = req.Name
			// newPath, _ := repoManager.GetRepoPath(username, repo.Name)
			// if err := repoManager.RenameRepo(oldPath, newPath); err != nil { ... }
		}
		repo.IsPublic = !req.Private

		if err := repoService.Update(repo); err != nil {
			http.Error(w, "Failed to update repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		render.JSON(w, r, RepoResponse{
			ID:        repo.ID,
			Name:      repo.Name,
			Owner:     repo.Owner.Username, // Assuming Owner is preloaded or handled by service
			OwnerID:   repo.OwnerID,
			Private:   !repo.IsPublic,
			CreatedAt: repo.CreatedAt.Format(http.TimeFormat),
			UpdatedAt: repo.UpdatedAt.Format(http.TimeFormat),
		})
	}
}

// DeleteRepository deletes a repository
func DeleteRepository(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		repoName := chi.URLParam(r, "repo")
		username := chi.URLParam(r, "username")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if user.ID != repo.OwnerID {
			// Consider if Admin can delete, currently only Owner
			http.Error(w, "Only repository owner can delete the repository", http.StatusForbidden)
			return
		}

		// It's generally better to delete files first, then DB record,
		// or use a transaction if possible, though transactions across FS and DB are complex.
		// Current logic: delete DB then files. If file deletion fails, DB is already gone.
		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok {
			http.Error(w, "Repository manager not found, cannot delete repository files", http.StatusInternalServerError)
			// Attempt to delete DB record anyway or revert? For now, error out.
			return
		}

		if err := repoManager.DeleteRepo(username, repoName); err != nil {
			// Log this error. The DB record is NOT YET deleted.
			// Decide if we proceed to delete DB record or not.
			// If we proceed, the error to client should indicate partial success.
			// For now, let's fail before DB deletion if file deletion fails.
			http.Error(w, "Failed to delete repository files: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := repoService.Delete(repo.ID); err != nil {
			// This is now a problem: files are deleted but DB record failed to delete.
			// This needs careful error handling, perhaps marking for cleanup.
			http.Error(w, "Failed to delete repository from database (files were deleted): "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ListUserRepositories lists repositories for a user
func ListUserRepositories(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		userService, ok := r.Context().Value("userService").(models.UserService)
		if !ok {
			http.Error(w, "User service not found", http.StatusInternalServerError)
			return
		}
		targetUser, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		limit := 20
		offset := 0

		limitParam := r.URL.Query().Get("limit")
		if limitParam != "" {
			parsedLimit, err := strconv.Atoi(limitParam)
			if err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}

		cursorParam := r.URL.Query().Get("cursor") // Using "cursor" as offset
		if cursorParam != "" {
			parsedOffset, err := strconv.Atoi(cursorParam)
			if err == nil && parsedOffset > 0 {
				offset = parsedOffset
			}
		}

		currentUser := auth.GetUserFromContext(r.Context())

		// This should ideally also fetch repositories where currentUser has explicit permissions,
		// not just public ones or ones they own. This requires a more complex query in repoService.
		// For now, sticking to current logic: targetUser's repos, filtered by public or currentUser is owner.
		repos, err := repoService.ListByOwner(targetUser.ID, limit, offset)
		if err != nil {
			http.Error(w, "Failed to list repositories: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var filteredRepos []RepoResponse
		for _, repo := range repos {
			// Permission check: repo is public OR current user is owner OR current user has specific permission
			// The third part (specific permission) is missing here and in canAccessRepository for listing context.
			canView := repo.IsPublic
			if currentUser != nil {
				if currentUser.ID == repo.OwnerID {
					canView = true
				} else if !canView { // If not public and not owner, check explicit perms
					// This part is missing. Need to call permService.HasPermission
					// permService, ok := r.Context().Value("permissionService").(models.PermissionService)
					// if ok { ... permService.HasPermission(currentUser.ID, repo.ID, models.ReadPermission) ... }
				}
			}

			if canView {
				// Owner username should come from repo.Owner.Username if preloaded by service
				ownerUsername := targetUser.Username // Fallback, but ideally repo.Owner is populated
				if repo.Owner.ID != 0 {
					ownerUsername = repo.Owner.Username
				}
				filteredRepos = append(filteredRepos, RepoResponse{
					ID:        repo.ID,
					Name:      repo.Name,
					Owner:     ownerUsername,
					OwnerID:   repo.OwnerID,
					Private:   !repo.IsPublic,
					CreatedAt: repo.CreatedAt.Format(http.TimeFormat),
					UpdatedAt: repo.UpdatedAt.Format(http.TimeFormat),
				})
			}
		}

		render.JSON(w, r, map[string]interface{}{
			"repositories": filteredRepos,
			"next_cursor":  offset + len(filteredRepos), // Simple cursor, assumes sequential IDs or stable sort
		})
	}
}

// ForkRepository creates a fork of an existing repository
func ForkRepository(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		repoName := chi.URLParam(r, "repo")
		username := chi.URLParam(r, "username") // owner of the source repo

		sourceRepo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Source repository not found", http.StatusNotFound)
			return
		}

		// Check if user can read the source repository
		if !sourceRepo.IsPublic {
			// This needs canAccessRepository logic or direct permission check
			// For now, assuming direct check as helper is not yet moved.
			canReadSource := false
			if user.ID == sourceRepo.OwnerID {
				canReadSource = true
			} else {
				permService, ok := r.Context().Value("permissionService").(models.PermissionService)
				if !ok {
					http.Error(w, "Permission service not found", http.StatusInternalServerError)
					return
				}
				hasAccess, _ := permService.HasPermission(user.ID, sourceRepo.ID, models.ReadPermission)
				if hasAccess {
					canReadSource = true
				}
			}
			if !canReadSource {
				http.Error(w, "Unauthorized to read source repository", http.StatusUnauthorized)
				return
			}
		}

		// Create Forked Repo DB Entry
		// Defaulting fork to public if source is public, private otherwise.
		// User might want to specify this.
		var forkReq RepoRequest // Use a request struct if more options for fork
		if errBody := json.NewDecoder(r.Body).Decode(&forkReq); errBody != nil {
			// Allow empty body, use defaults. If body exists and is bad, then error.
			// For now, assume no body or body provides new name/description/privacy.
			// If no request body, use source name. Potentially problematic if user already has repo with that name.
			// The repoService.Create should handle name conflicts for the new owner.
		}

		forkedRepoName := sourceRepo.Name
		if forkReq.Name != "" {
			forkedRepoName = forkReq.Name
		}

		forkedRepo := &models.Repository{
			Name:     forkedRepoName, // User might want to rename fork
			OwnerID:  user.ID,
			IsPublic: !forkReq.Private, // User can decide if fork is private
			// Description: forkReq.Description, // if provided
			// ForkedFromID: &sourceRepo.ID, // Add this to model if you want to track fork lineage
		}

		if err := repoService.Create(forkedRepo); err != nil {
			http.Error(w, "Failed to create forked repository entry: "+err.Error(), http.StatusInternalServerError)
			return
		}

		repoManager, ok := r.Context().Value("repoManager").(*repository.Manager)
		if !ok {
			// DB entry created, but files cannot be copied. Critical error.
			// Should attempt to delete forkedRepo DB entry.
			repoService.Delete(forkedRepo.ID) // Attempt cleanup
			http.Error(w, "Repository manager not found, cannot copy repository files", http.StatusInternalServerError)
			return
		}

		sourceRepoOwnerUsername := username // username from chi.URLParam
		if sourceRepo.Owner.ID != 0 {       // If Owner was preloaded by GetByUsername
			sourceRepoOwnerUsername = sourceRepo.Owner.Username
		}
		_ = sourceRepoOwnerUsername // Acknowledge use for upcoming TODO

		// Copy repository files
		// CreateRepo will init an empty repo. We need a CopyRepo or similar.
		// For now, it creates an empty repository structure, actual data copy is a TODO.
		_, err = repoManager.CreateRepo(user.Username, forkedRepo.Name) // Creates empty structure
		if err != nil {
			repoService.Delete(forkedRepo.ID) // Attempt cleanup
			http.Error(w, "Failed to create directory for forked repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Implement actual data copy for fork operation using repoManager.
		// e.g., repoManager.CopyRepo(sourceOwnerUsername, sourceRepo.Name, user.Username, forkedRepo.Name)
		// This would involve copying .vec directory contents.

		render.Status(r, http.StatusCreated)
		render.JSON(w, r, RepoResponse{
			ID:        forkedRepo.ID,
			Name:      forkedRepo.Name,
			Owner:     user.Username,
			OwnerID:   user.ID,
			Private:   !forkedRepo.IsPublic,
			CreatedAt: forkedRepo.CreatedAt.Format(http.TimeFormat),
			// Description: forkedRepo.Description,
		})
	}
}
