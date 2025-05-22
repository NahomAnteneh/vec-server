package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// RepoResponse represents the response format for repository operations
type RepoResponse struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	OwnerID     uint   `json:"owner_id"`
	Description string `json:"description,omitempty"` // May be added to repository model later
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
func CreateRepository(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req RepoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Name == "" {
			http.Error(w, "Repository name is required", http.StatusBadRequest)
			return
		}

		// Create repository
		repo := &models.Repository{
			Name:     req.Name,
			OwnerID:  user.ID,
			IsPublic: !req.Private,
			Path:     filepath.Join("repos", user.Username, req.Name),
		}

		if err := repoService.Create(repo); err != nil {
			http.Error(w, "Failed to create repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return response
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
func GetRepository(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get repository name from URL
		repoName := chi.URLParam(r, "repoName")
		username := chi.URLParam(r, "username")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check permissions if repository is private
		if !repo.IsPublic {
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if user.ID != repo.OwnerID {
				hasAccess, _ := hasRepoAccess(r, repo.ID, user.ID)
				if !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		// Return repository data
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
func UpdateRepository(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository ID from URL
		repoName := chi.URLParam(r, "repoName")
		username := chi.URLParam(r, "username")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if user has admin permissions
		if user.ID != repo.OwnerID {
			hasAdmin, _ := hasAdminPermission(r, repo.ID, user.ID)
			if !hasAdmin {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Parse request body
		var req RepoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Update repository
		if req.Name != "" && req.Name != repo.Name {
			repo.Name = req.Name
		}
		repo.IsPublic = !req.Private

		if err := repoService.Update(repo); err != nil {
			http.Error(w, "Failed to update repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return updated repository data
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

// DeleteRepository deletes a repository
func DeleteRepository(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository ID from URL
		repoName := chi.URLParam(r, "repoName")
		username := chi.URLParam(r, "username")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Only the owner can delete a repository
		if user.ID != repo.OwnerID {
			http.Error(w, "Only repository owner can delete the repository", http.StatusForbidden)
			return
		}

		// Delete repository
		if err := repoService.Delete(repo.ID); err != nil {
			http.Error(w, "Failed to delete repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success with no content
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListUserRepositories lists repositories for a user
func ListUserRepositories(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		// Get user ID
		userService := r.Context().Value("userService").(*models.UserService)
		targetUser, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Parse pagination parameters
		limit := 20 // Default limit
		offset := 0 // Default offset

		limitParam := r.URL.Query().Get("limit")
		if limitParam != "" {
			parsedLimit, err := strconv.Atoi(limitParam)
			if err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}

		cursorParam := r.URL.Query().Get("cursor")
		if cursorParam != "" {
			parsedOffset, err := strconv.Atoi(cursorParam)
			if err == nil && parsedOffset > 0 {
				offset = parsedOffset
			}
		}

		// Get authenticated user for private repo access
		currentUser := auth.GetUserFromContext(r.Context())

		// Get repositories
		repos, err := repoService.ListByOwner(targetUser.ID, limit, offset)
		if err != nil {
			http.Error(w, "Failed to list repositories: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Filter out private repositories if the user is not the owner
		var filteredRepos []RepoResponse
		for _, repo := range repos {
			// Include repository if it's public or if the current user is the owner
			if repo.IsPublic || (currentUser != nil && currentUser.ID == repo.OwnerID) {
				filteredRepos = append(filteredRepos, RepoResponse{
					ID:        repo.ID,
					Name:      repo.Name,
					Owner:     targetUser.Username,
					OwnerID:   repo.OwnerID,
					Private:   !repo.IsPublic,
					CreatedAt: repo.CreatedAt.Format(http.TimeFormat),
				})
			}
		}

		// Return paginated result
		render.JSON(w, r, map[string]interface{}{
			"repositories": filteredRepos,
			"next_cursor":  offset + len(filteredRepos),
		})
	}
}

// ForkRepository creates a fork of an existing repository
func ForkRepository(repoService *models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository ID from URL
		repoName := chi.URLParam(r, "repoName")
		username := chi.URLParam(r, "username")

		// Get source repository
		sourceRepo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if user has read access to the source repository
		if !sourceRepo.IsPublic {
			hasAccess, _ := hasRepoAccess(r, sourceRepo.ID, user.ID)
			if !hasAccess {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Create forked repository
		forkedRepo := &models.Repository{
			Name:     sourceRepo.Name,
			OwnerID:  user.ID,
			IsPublic: sourceRepo.IsPublic,
		}

		if err := repoService.Create(forkedRepo); err != nil {
			http.Error(w, "Failed to fork repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Implement actual forking of repository files
		// This would involve copying the actual repository data files

		// Return response
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, RepoResponse{
			ID:        forkedRepo.ID,
			Name:      forkedRepo.Name,
			Owner:     user.Username,
			OwnerID:   user.ID,
			Private:   !forkedRepo.IsPublic,
			CreatedAt: forkedRepo.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// Helper functions

// hasRepoAccess checks if a user has at least read access to a repository
func hasRepoAccess(r *http.Request, repoID, userID uint) (bool, error) {
	permissionService := r.Context().Value("permissionService").(*models.PermissionService)
	return permissionService.HasPermission(userID, repoID, models.ReadPermission)
}

// hasAdminPermission checks if a user has admin access to a repository
func hasAdminPermission(r *http.Request, repoID, userID uint) (bool, error) {
	permissionService := r.Context().Value("permissionService").(*models.PermissionService)
	return permissionService.HasPermission(userID, repoID, models.AdminPermission)
}
