package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"gorm.io/gorm"
)

// contextKey is a custom type to avoid collisions in the context value map
type contextKey string

// AuthenticatedUserKey is the key used to store the authenticated user in the context
const AuthenticatedUserKey contextKey = "authenticated_user"

// RequirePermission returns middleware that ensures the user has the required permission
func RequirePermission(accessLevel string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get repository context values
			repoContext := GetRepositoryFromContext(r.Context())
			if repoContext == nil {
				http.Error(w, "Repository not found", http.StatusNotFound)
				return
			}

			// Get user from context
			user := GetAuthenticatedUser(r.Context())
			if user == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check if the user is the repository owner (owners have implicit admin access)
			if repoContext.Repository.OwnerID == user.ID {
				next.ServeHTTP(w, r)
				return
			}

			// For public repositories, allow read access without authentication
			if repoContext.Repository.IsPublic && accessLevel == models.ReadPermission {
				next.ServeHTTP(w, r)
				return
			}

			// Check permissions
			permService := models.NewPermissionService(repoContext.DB)
			hasPermission, err := permService.HasPermission(user.ID, repoContext.Repository.ID, accessLevel)
			if err != nil {
				http.Error(w, "Error checking permissions", http.StatusInternalServerError)
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

// AuthenticationMiddleware authenticates the user from the request and adds the user to the context
func AuthenticationMiddleware(cfg *config.Config, db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No auth required for public repositories on read operations
			if isReadOnlyRequest(r) {
				// We'll check later if the repository is public
				next.ServeHTTP(w, r)
				return
			}

			// Get Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
				next.ServeHTTP(w, r) // Continue without auth for now
				return
			}

			// Handle different auth methods
			if strings.HasPrefix(authHeader, "Basic ") {
				handleBasicAuth(w, r, next, db)
				return
			} else if strings.HasPrefix(authHeader, "Bearer ") {
				handleBearerAuth(w, r, next, cfg, db)
				return
			}

			// Invalid auth method
			w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
			next.ServeHTTP(w, r) // Continue without auth for now
		})
	}
}

// handleBasicAuth handles HTTP Basic Authentication
func handleBasicAuth(w http.ResponseWriter, r *http.Request, next http.Handler, db *gorm.DB) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
		http.Error(w, "Invalid authentication credentials", http.StatusUnauthorized)
		return
	}

	// Get user from database
	userService := models.NewUserService(db)
	user, err := userService.GetByUsername(username)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
		http.Error(w, "Invalid authentication credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	if !user.CheckPassword(password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server"`)
		http.Error(w, "Invalid authentication credentials", http.StatusUnauthorized)
		return
	}

	// Add user to context
	ctx := context.WithValue(r.Context(), AuthenticatedUserKey, user)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// handleBearerAuth handles JWT token authentication
func handleBearerAuth(w http.ResponseWriter, r *http.Request, next http.Handler, cfg *config.Config, db *gorm.DB) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token
	claims, err := auth.VerifyToken(tokenString, cfg.JWTSecret)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Get user from database
	userService := models.NewUserService(db)
	user, err := userService.GetByID(claims.UserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Add user to context
	ctx := context.WithValue(r.Context(), AuthenticatedUserKey, user)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// GetAuthenticatedUser retrieves the authenticated user from the context
func GetAuthenticatedUser(ctx context.Context) *models.User {
	if user, ok := ctx.Value(AuthenticatedUserKey).(*models.User); ok {
		return user
	}
	return nil
}

// isReadOnlyRequest checks if the request is read-only
func isReadOnlyRequest(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
}
