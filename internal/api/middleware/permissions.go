package middleware

import (
	"net/http"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// RequireAdmin ensures the user is an admin
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil || !user.IsAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission ensures the user has the specified permission level
func RequirePermission(level string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			repoCtx, ok := r.Context().Value(RepositoryContextKey).(*RepositoryContext)
			if !ok || repoCtx.Repository == nil {
				http.Error(w, "Repository context not found", http.StatusInternalServerError)
				return
			}

			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			permService, ok := r.Context().Value("permissionService").(models.PermissionService)
			if !ok {
				http.Error(w, "Permission service not found", http.StatusInternalServerError)
				return
			}

			hasPermission, err := permService.HasPermission(user.ID, repoCtx.Repository.ID, level)
			if err != nil {
				http.Error(w, "Error checking permissions: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if !hasPermission {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PublicReadOrRequirePermission allows public access for read operations on public repositories,
// otherwise requires authentication and proper permissions
func PublicReadOrRequirePermission(level string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			repoCtx, ok := r.Context().Value(RepositoryContextKey).(*RepositoryContext)
			if !ok || repoCtx.Repository == nil {
				http.Error(w, "Repository context not found", http.StatusInternalServerError)
				return
			}

			// For public repositories and read operations (GET, HEAD), allow access without authentication
			if repoCtx.Repository.IsPublic && level == models.ReadPermission {
				next.ServeHTTP(w, r)
				return
			}

			// Otherwise, require authentication and permission
			user := auth.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			permService, ok := r.Context().Value("permissionService").(models.PermissionService)
			if !ok {
				http.Error(w, "Permission service not found", http.StatusInternalServerError)
				return
			}

			hasPermission, err := permService.HasPermission(user.ID, repoCtx.Repository.ID, level)
			if err != nil {
				http.Error(w, "Error checking permissions: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if !hasPermission {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
