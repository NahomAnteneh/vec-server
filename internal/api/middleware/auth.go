package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"gorm.io/gorm"
)

// contextKey is a custom type for keys local to this middleware package.
type contextKey string

// Context keys local to this middleware package
const (
	RepositoryContextKey contextKey = "repository_context"
	RequestIDKey         contextKey = "request_id"
)

// RepositoryContext contains repository-related data
type RepositoryContext struct {
	Repository *models.Repository
	DB         *gorm.DB
}

// GetRepositoryFromContext retrieves the repository context from the context
func GetRepositoryFromContext(ctx context.Context) *RepositoryContext {
	if repo, ok := ctx.Value(RepositoryContextKey).(*RepositoryContext); ok {
		return repo
	}
	return nil
}

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

			// Get user from context using the central auth package's function
			user := auth.GetUserFromContext(r.Context())
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

			// Try multiple authentication methods in order
			user := tryAuthMethods(r, cfg, db)

			if user != nil {
				// Auth successful, add user to context
				ctx := context.WithValue(r.Context(), auth.AuthenticatedUserKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No valid authentication provided
			w.Header().Set("WWW-Authenticate", `Basic realm="Vec Server", Bearer`)
			next.ServeHTTP(w, r) // Continue without auth for now
		})
	}
}

// tryAuthMethods attempts to authenticate using various methods
func tryAuthMethods(r *http.Request, cfg *config.Config, db *gorm.DB) *models.User {
	// 1. Try Authorization header (Bearer or Basic)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Basic ") {
			user := authenticateBasic(r, db)
			if user != nil {
				return user
			}
		} else if strings.HasPrefix(authHeader, "Bearer ") {
			user := authenticateBearer(r, cfg, db)
			if user != nil {
				return user
			}
		}
	}

	// 2. Try custom header authentication
	user := authenticateCustomHeader(r, cfg, db)
	if user != nil {
		return user
	}

	return nil
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
	ctx := context.WithValue(r.Context(), auth.AuthenticatedUserKey, user)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// authenticateBasic attempts to authenticate using Basic auth
func authenticateBasic(r *http.Request, db *gorm.DB) *models.User {
	username, password, ok := r.BasicAuth()
	log.Printf("authenticateBasic: Username='%s', PasswordSet=%t, BasicAuthOK=%t", username, password != "", ok)
	if !ok {
		log.Println("authenticateBasic: r.BasicAuth() not ok")
		return nil
	}

	// Get user from database
	userService := models.NewUserService(db)
	user, err := userService.GetByUsername(username)
	if err != nil {
		log.Printf("authenticateBasic: userService.GetByUsername('%s') failed: %v", username, err)
		return nil
	}
	log.Printf("authenticateBasic: Found user ID %d for username '%s'", user.ID, username)

	// Verify password
	passwordMatch := user.CheckPassword(password)
	log.Printf("authenticateBasic: user.CheckPassword for user ID %d result: %t", user.ID, passwordMatch)
	if !passwordMatch {
		log.Printf("authenticateBasic: Password mismatch for user ID %d", user.ID)
		return nil
	}

	log.Printf("authenticateBasic: Authentication successful for user ID %d (%s)", user.ID, username)
	return user
}

// handleBearerAuth handles JWT token authentication
func handleBearerAuth(w http.ResponseWriter, r *http.Request, next http.Handler, cfg *config.Config, db *gorm.DB) {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token
	claims, err := auth.VerifyJWTToken(tokenString, cfg.JWTSecret)
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
	ctx := context.WithValue(r.Context(), auth.AuthenticatedUserKey, user)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// authenticateBearer attempts to authenticate using Bearer token
func authenticateBearer(r *http.Request, cfg *config.Config, db *gorm.DB) *models.User {
	authHeader := r.Header.Get("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify token
	claims, err := auth.VerifyJWTToken(tokenString, cfg.JWTSecret)
	if err != nil {
		return nil
	}

	// Get user from database
	userService := models.NewUserService(db)
	user, err := userService.GetByID(claims.UserID)
	if err != nil {
		return nil
	}

	return user
}

// authenticateCustomHeader attempts to authenticate using custom header configuration
func authenticateCustomHeader(r *http.Request, cfg *config.Config, db *gorm.DB) *models.User {
	// Check if we have custom header auth configured
	if cfg.Auth.CustomHeaderName == "" {
		return nil
	}

	// Get the header value
	headerValue := r.Header.Get(cfg.Auth.CustomHeaderName)
	if headerValue == "" {
		return nil
	}

	// For username-based custom header
	if cfg.Auth.CustomHeaderType == "username" {
		userService := models.NewUserService(db)
		user, err := userService.GetByUsername(headerValue)
		if err != nil {
			return nil
		}
		return user
	}

	// For token-based custom header
	if cfg.Auth.CustomHeaderType == "token" {
		// Verify token
		claims, err := auth.VerifyJWTToken(headerValue, cfg.JWTSecret)
		if err != nil {
			return nil
		}

		// Get user from database
		userService := models.NewUserService(db)
		user, err := userService.GetByID(claims.UserID)
		if err != nil {
			return nil
		}
		return user
	}

	return nil
}

// isReadOnlyRequest checks if the request is read-only
func isReadOnlyRequest(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}
