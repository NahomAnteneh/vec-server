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
func AddCollaborator(userService models.UserService, repoService models.RepositoryService, permService models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repo")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		var req PermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.AccessLevel == "" {
			http.Error(w, "Username and access level are required", http.StatusBadRequest)
			return
		}

		if !isValidAccessLevel(req.AccessLevel) {
			http.Error(w, "Invalid access level. Must be 'read', 'write', or 'admin'", http.StatusBadRequest)
			return
		}

		collaborator, err := userService.GetByUsername(req.Username)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		existingPerm, err := permService.GetByUserAndRepo(collaborator.ID, repo.ID)
		if err == nil && existingPerm != nil {
			http.Error(w, "User is already a collaborator", http.StatusConflict)
			return
		}

		perm := &models.Permission{
			UserID:       collaborator.ID,
			RepositoryID: repo.ID,
			AccessLevel:  req.AccessLevel,
		}

		if err := permService.Create(perm); err != nil {
			http.Error(w, "Failed to add collaborator: "+err.Error(), http.StatusInternalServerError)
			return
		}

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
func RemoveCollaborator(userService models.UserService, repoService models.RepositoryService, permService models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repo")
		collaboratorUsername := chi.URLParam(r, "collaboratorUsername")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		collaborator, err := userService.GetByUsername(collaboratorUsername)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		if collaborator.ID == repo.OwnerID {
			http.Error(w, "Cannot remove repository owner", http.StatusForbidden)
			return
		}

		err = permService.DeleteByUserAndRepo(collaborator.ID, repo.ID)
		if err != nil {
			http.Error(w, "Failed to remove collaborator: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UpdateCollaboratorPermissions changes a user's access level
func UpdateCollaboratorPermissions(userService models.UserService, repoService models.RepositoryService, permService models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repo")
		collaboratorUsername := chi.URLParam(r, "collaboratorUsername")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if authUser.ID != repo.OwnerID {
			hasAdmin, err := permService.HasPermission(authUser.ID, repo.ID, models.AdminPermission)
			if err != nil || !hasAdmin {
				http.Error(w, "Admin permissions required", http.StatusForbidden)
				return
			}
		}

		collaborator, err := userService.GetByUsername(collaboratorUsername)
		if err != nil {
			http.Error(w, "Collaborator user not found", http.StatusNotFound)
			return
		}

		if collaborator.ID == repo.OwnerID {
			http.Error(w, "Cannot modify repository owner permissions", http.StatusForbidden)
			return
		}

		var req PermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if !isValidAccessLevel(req.AccessLevel) {
			http.Error(w, "Invalid access level. Must be 'read', 'write', or 'admin'", http.StatusBadRequest)
			return
		}

		perm, err := permService.GetByUserAndRepo(collaborator.ID, repo.ID)
		if err != nil {
			http.Error(w, "Collaborator does not have access to this repository", http.StatusNotFound)
			return
		}

		perm.AccessLevel = req.AccessLevel
		if err := permService.Update(perm); err != nil {
			http.Error(w, "Failed to update permissions: "+err.Error(), http.StatusInternalServerError)
			return
		}

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
func ListCollaborators(repoService models.RepositoryService, permService models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repo")

		repo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if !repo.IsPublic {
			authUser := auth.GetUserFromContext(r.Context())
			if authUser == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if authUser.ID != repo.OwnerID {
				hasAccess, err := permService.HasPermission(authUser.ID, repo.ID, models.ReadPermission)
				if err != nil || !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		permissions, err := permService.ListByRepository(repo.ID)
		if err != nil {
			http.Error(w, "Failed to list collaborators: "+err.Error(), http.StatusInternalServerError)
			return
		}

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
func GetUserPermission(userService models.UserService, repoService models.RepositoryService, permService models.PermissionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoUsername := chi.URLParam(r, "username")
		repoName := chi.URLParam(r, "repo")
		targetUsername := chi.URLParam(r, "targetUsername")

		repo, err := repoService.GetByUsername(repoUsername, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		targetUser, err := userService.GetByUsername(targetUsername)
		if err != nil {
			http.Error(w, "Target user not found", http.StatusNotFound)
			return
		}

		if !repo.IsPublic {
			authUser := auth.GetUserFromContext(r.Context())
			if authUser == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if authUser.ID != repo.OwnerID {
				hasAccess, err := permService.HasPermission(authUser.ID, repo.ID, models.ReadPermission)
				if err != nil || !hasAccess {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		if targetUser.ID == repo.OwnerID {
			render.JSON(w, r, map[string]interface{}{
				"username":     targetUser.Username,
				"user_id":      targetUser.ID,
				"repo_name":    repo.Name,
				"repo_id":      repo.ID,
				"access_level": "owner",
			})
			return
		}

		permission, err := permService.GetByUserAndRepo(targetUser.ID, repo.ID)
		if err != nil {
			if repo.IsPublic {
				render.JSON(w, r, map[string]interface{}{
					"username":     targetUser.Username,
					"user_id":      targetUser.ID,
					"repo_name":    repo.Name,
					"repo_id":      repo.ID,
					"access_level": models.ReadPermission,
				})
				return
			}

			render.JSON(w, r, map[string]interface{}{
				"username":     targetUser.Username,
				"user_id":      targetUser.ID,
				"repo_name":    repo.Name,
				"repo_id":      repo.ID,
				"access_level": "none",
			})
			return
		}

		render.JSON(w, r, map[string]interface{}{
			"username":     targetUser.Username,
			"user_id":      targetUser.ID,
			"repo_name":    repo.Name,
			"repo_id":      repo.ID,
			"access_level": permission.AccessLevel,
		})
	}
}

// isValidAccessLevel checks if an access level is valid
func isValidAccessLevel(level string) bool {
	return level == models.ReadPermission || level == models.WritePermission || level == models.AdminPermission
}
