package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// PermissionRequest represents the request format for adding/updating collaborator permissions
type PermissionRequest struct {
	Username    string `json:"username"`
	AccessLevel string `json:"access_level"`
}

// PermissionResponse represents the response format for permission operations
type PermissionResponse struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	UserID      uint   `json:"user_id"`
	RepoName    string `json:"repo_name"`
	RepoID      uint   `json:"repo_id"`
	AccessLevel string `json:"access_level"`
	CreatedAt   string `json:"created_at"`
}

// AddCollaborator adds a user to a repository with specified permissions
func AddCollaborator(userService *models.UserService, repoService *models.RepositoryService, permService *models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository from URL params
		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repoName")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if authenticated user has admin permissions
		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		// Parse request body
		var req PermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Username == "" || req.AccessLevel == "" {
			http.Error(w, "Username and access level are required", http.StatusBadRequest)
			return
		}

		// Validate access level
		if !isValidAccessLevel(req.AccessLevel) {
			http.Error(w, "Invalid access level. Must be 'read', 'write', or 'admin'", http.StatusBadRequest)
			return
		}

		// Get user by username
		collaborator, err := userService.GetByUsername(req.Username)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		// Check if permission already exists
		existingPerm, err := permService.GetByUserAndRepo(collaborator.ID, repo.ID)
		if err == nil && existingPerm != nil {
			http.Error(w, "User is already a collaborator", http.StatusConflict)
			return
		}

		// Create permission
		perm := &models.Permission{
			UserID:       collaborator.ID,
			RepositoryID: repo.ID,
			AccessLevel:  req.AccessLevel,
		}

		if err := permService.Create(perm); err != nil {
			http.Error(w, "Failed to add collaborator: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, PermissionResponse{
			ID:          perm.ID,
			Username:    collaborator.Username,
			UserID:      collaborator.ID,
			RepoName:    repo.Name,
			RepoID:      repo.ID,
			AccessLevel: perm.AccessLevel,
			CreatedAt:   perm.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// RemoveCollaborator removes a user's access to a repository
func RemoveCollaborator(userService *models.UserService, repoService *models.RepositoryService, permService *models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository from URL params
		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repoName")
		collaboratorUsername := chi.URLParam(r, "collaboratorUsername")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if authenticated user has admin permissions
		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		// Get collaborator by username
		collaborator, err := userService.GetByUsername(collaboratorUsername)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		// Cannot remove the owner
		if collaborator.ID == repo.OwnerID {
			http.Error(w, "Cannot remove repository owner", http.StatusForbidden)
			return
		}

		// Delete permission
		err = permService.DeleteByUserAndRepo(collaborator.ID, repo.ID)
		if err != nil {
			http.Error(w, "Failed to remove collaborator: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success with no content
		w.WriteHeader(http.StatusNoContent)
	}
}

// UpdateCollaboratorPermissions changes a user's access level
func UpdateCollaboratorPermissions(userService *models.UserService, repoService *models.RepositoryService, permService *models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get repository from URL params
		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repoName")
		collaboratorUsername := chi.URLParam(r, "collaboratorUsername")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if authenticated user has admin permissions
		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		// Get collaborator by username
		collaborator, err := userService.GetByUsername(collaboratorUsername)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		// Cannot modify the owner's permissions
		if collaborator.ID == repo.OwnerID {
			http.Error(w, "Cannot modify repository owner permissions", http.StatusForbidden)
			return
		}

		// Parse request body
		var req PermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate access level
		if !isValidAccessLevel(req.AccessLevel) {
			http.Error(w, "Invalid access level. Must be 'read', 'write', or 'admin'", http.StatusBadRequest)
			return
		}

		// Get existing permission
		perm, err := permService.GetByUserAndRepo(collaborator.ID, repo.ID)
		if err != nil {
			http.Error(w, "Collaborator does not have access to this repository", http.StatusNotFound)
			return
		}

		// Update permission
		perm.AccessLevel = req.AccessLevel
		if err := permService.Update(perm); err != nil {
			http.Error(w, "Failed to update permissions: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return updated permission
		render.JSON(w, r, PermissionResponse{
			ID:          perm.ID,
			Username:    collaborator.Username,
			UserID:      collaborator.ID,
			RepoName:    repo.Name,
			RepoID:      repo.ID,
			AccessLevel: perm.AccessLevel,
			CreatedAt:   perm.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// ListCollaborators shows all users with access to the repository
func ListCollaborators(repoService *models.RepositoryService, permService *models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get repository from URL params
		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repoName")

		// Get repository
		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Check if repository is private
		if !repo.IsPublic {
			// Get authenticated user
			authUser := auth.GetUserFromContext(r.Context())
			if authUser == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if authenticated user has read access
			if authUser.ID != repo.OwnerID {
				hasAccess, err := permService.HasPermission(authUser.ID, repo.ID, models.ReadPermission)
				if err != nil || !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		// Get all collaborators
		permissions, err := permService.ListByRepository(repo.ID)
		if err != nil {
			http.Error(w, "Failed to list collaborators: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Format response
		var collaborators []PermissionResponse
		for _, perm := range permissions {
			collaborators = append(collaborators, PermissionResponse{
				ID:          perm.ID,
				Username:    perm.User.Username,
				UserID:      perm.UserID,
				RepoName:    repo.Name,
				RepoID:      repo.ID,
				AccessLevel: perm.AccessLevel,
				CreatedAt:   perm.CreatedAt.Format(http.TimeFormat),
			})
		}

		// Return collaborators list
		render.JSON(w, r, map[string]interface{}{
			"collaborators": collaborators,
			"owner": map[string]interface{}{
				"username":     repo.Owner.Username,
				"id":           repo.OwnerID,
				"access_level": "owner",
			},
		})
	}
}

// GetUserPermission checks a specific user's access level
func GetUserPermission(userService *models.UserService, repoService *models.RepositoryService, permService *models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get repository from URL params
		repoUsername := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repoName")
		targetUsername := chi.URLParam(r, "targetUsername")

		// Get repository
		repo, err := repoService.GetByUsername(repoUsername, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Get target user
		targetUser, err := userService.GetByUsername(targetUsername)
		if err != nil {
			http.Error(w, "Target user not found", http.StatusNotFound)
			return
		}

		// Check if repository is private and the requester has access
		if !repo.IsPublic {
			// Get authenticated user
			authUser := auth.GetUserFromContext(r.Context())
			if authUser == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if authenticated user has read access
			if authUser.ID != repo.OwnerID {
				hasAccess, err := permService.HasPermission(authUser.ID, repo.ID, models.ReadPermission)
				if err != nil || !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		// If target user is the repository owner
		if targetUser.ID == repo.OwnerID {
			render.JSON(w, r, map[string]interface{}{
				"username":     targetUser.Username,
				"user_id":      targetUser.ID,
				"repo_name":    repo.Name,
				"repo_id":      repo.ID,
				"access_level": "owner", // Owner has implicit admin rights
			})
			return
		}

		// Check if user has explicit permissions
		permission, err := permService.GetByUserAndRepo(targetUser.ID, repo.ID)
		if err != nil {
			// For public repositories, all users have at least read access
			if repo.IsPublic {
				render.JSON(w, r, map[string]interface{}{
					"username":     targetUser.Username,
					"user_id":      targetUser.ID,
					"repo_name":    repo.Name,
					"repo_id":      repo.ID,
					"access_level": models.ReadPermission, // Public repos provide read access
				})
				return
			}

			// No access for private repos
			render.JSON(w, r, map[string]interface{}{
				"username":     targetUser.Username,
				"user_id":      targetUser.ID,
				"repo_name":    repo.Name,
				"repo_id":      repo.ID,
				"access_level": "none", // No access
			})
			return
		}

		// Return user's explicit permission
		render.JSON(w, r, map[string]interface{}{
			"username":     targetUser.Username,
			"user_id":      targetUser.ID,
			"repo_name":    repo.Name,
			"repo_id":      repo.ID,
			"access_level": permission.AccessLevel,
		})
	}
}

// Helper functions

// isValidAccessLevel checks if an access level is valid
func isValidAccessLevel(level string) bool {
	return level == models.ReadPermission || level == models.WritePermission || level == models.AdminPermission
}
