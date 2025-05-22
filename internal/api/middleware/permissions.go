package middleware

import (
	"net/http"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/go-chi/render"
	"gorm.io/gorm"
)

// PermissionsMiddleware checks if the user has permission to access the repository
func PermissionsMiddleware(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get repository context
			repoContext := GetRepositoryFromContext(r.Context())
			if repoContext == nil {
				http.Error(w, "Repository not found", http.StatusNotFound)
				return
			}

			// Get authenticated user
			user := auth.GetUserFromContext(r.Context())

			// For public repositories with read-only requests, allow access without authentication
			if repoContext.Repository.IsPublic && isReadOnlyRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			// For all other requests, require authentication
			if user == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Repository owner has full access
			if repoContext.Repository.OwnerID == user.ID {
				next.ServeHTTP(w, r)
				return
			}

			// Determine required permission level based on request method
			requiredLevel := determineRequiredPermissionLevel(r)

			// Check if user has the required permission
			permService := models.NewPermissionService(db)
			hasPermission, err := permService.HasPermission(user.ID, repoContext.Repository.ID, requiredLevel)
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "Error checking permissions"})
				return
			}

			if !hasPermission {
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, map[string]string{"error": "Permission denied"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin ensures the user is an admin or owner of the repository
func RequireAdmin(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get repository context
			repoContext := GetRepositoryFromContext(r.Context())
			if repoContext == nil {
				http.Error(w, "Repository not found", http.StatusNotFound)
				return
			}

			// Get authenticated user
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Repository owner has implicit admin permission
			if repoContext.Repository.OwnerID == user.ID {
				next.ServeHTTP(w, r)
				return
			}

			// Check if user has admin permission
			permService := models.NewPermissionService(db)
			hasPermission, err := permService.HasPermission(user.ID, repoContext.Repository.ID, models.AdminPermission)
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "Error checking permissions"})
				return
			}

			if !hasPermission {
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, map[string]string{"error": "Admin permission required"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwner ensures the user is the owner of the repository
func RequireOwner(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get repository context
			repoContext := GetRepositoryFromContext(r.Context())
			if repoContext == nil {
				http.Error(w, "Repository not found", http.StatusNotFound)
				return
			}

			// Get authenticated user
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check if user is the repository owner
			if repoContext.Repository.OwnerID != user.ID {
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, map[string]string{"error": "Only the repository owner can perform this action"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// determineRequiredPermissionLevel returns the required permission level based on the request method
func determineRequiredPermissionLevel(r *http.Request) string {
	// For read-only methods, read permission is sufficient
	if isReadOnlyRequest(r) {
		return models.ReadPermission
	}

	// For methods that modify data, require write permission
	return models.WritePermission
}
