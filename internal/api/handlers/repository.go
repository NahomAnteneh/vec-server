package handlers

import (
	"encoding/json"
	"net/http"
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
				permService := r.Context().Value("permissionService").(models.PermissionService)
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
			repo.Name = req.Name
		}
		repo.IsPublic = !req.Private

		if err := repoService.Update(repo); err != nil {
			http.Error(w, "Failed to update repository: "+err.Error(), http.StatusInternalServerError)
			return
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
			http.Error(w, "Only repository owner can delete the repository", http.StatusForbidden)
			return
		}

		if err := repoService.Delete(repo.ID); err != nil {
			http.Error(w, "Failed to delete repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ListUserRepositories lists repositories for a user
func ListUserRepositories(repoService models.RepositoryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		userService := r.Context().Value("userService").(models.UserService)
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

		cursorParam := r.URL.Query().Get("cursor")
		if cursorParam != "" {
			parsedOffset, err := strconv.Atoi(cursorParam)
			if err == nil && parsedOffset > 0 {
				offset = parsedOffset
			}
		}

		currentUser := auth.GetUserFromContext(r.Context())

		repos, err := repoService.ListByOwner(targetUser.ID, limit, offset)
		if err != nil {
			http.Error(w, "Failed to list repositories: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var filteredRepos []RepoResponse
		for _, repo := range repos {
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

		render.JSON(w, r, map[string]interface{}{
			"repositories": filteredRepos,
			"next_cursor":  offset + len(filteredRepos),
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
		username := chi.URLParam(r, "username")

		sourceRepo, err := repoService.GetByUsername(username, repoName)
		if err != nil {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		if !sourceRepo.IsPublic {
			permService := r.Context().Value("permissionService").(models.PermissionService)
			hasAccess, _ := permService.HasPermission(user.ID, sourceRepo.ID, models.ReadPermission)
			if !hasAccess {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		forkedRepo := &models.Repository{
			Name:     sourceRepo.Name,
			OwnerID:  user.ID,
			IsPublic: sourceRepo.IsPublic,
		}

		if err := repoService.Create(forkedRepo); err != nil {
			http.Error(w, "Failed to fork repository: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Copy repository files using repoManager
		// repoManager := r.Context().Value("repoManager").(*repository.Manager)
		// if err := repoManager.CopyRepository(sourceRepo.Path, forkedRepo.Path); err != nil {
		//     http.Error(w, "Failed to copy repository files: "+err.Error(), http.StatusInternalServerError)
		//     return
		// }

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
