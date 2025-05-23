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
			http.Error(w, "Unauthorized: Authentication required with username/email and password hash", http.StatusUnauthorized)
			return
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

// authenticateBasic attempts to authenticate using Basic auth
// This implementation directly checks the provided password hash against the username
func authenticateBasic(r *http.Request, db *gorm.DB) *models.User {
	username, passwordHash, ok := r.BasicAuth()
	log.Printf("authenticateBasic: Username='%s', PasswordHashProvided=%t, BasicAuthOK=%t", username, passwordHash != "", ok)
	if !ok || username == "" || passwordHash == "" {
		log.Println("authenticateBasic: Invalid basic auth credentials")
		return nil
	}

	// Get user from database
	userService := models.NewUserService(db)
	user, err := userService.GetByUsername(username)
	if err != nil {
		// Try to find by email if username not found
		user, err = userService.GetByEmail(username)
		if err != nil {
			log.Printf("authenticateBasic: No user found with username/email '%s'", username)
			return nil
		}
	}
	log.Printf("authenticateBasic: Found user ID %d for username/email '%s'", user.ID, username)

	// Direct password hash comparison
	if user.PasswordHash != passwordHash {
		log.Printf("authenticateBasic: Password hash mismatch for user ID %d", user.ID)
		return nil
	}

	log.Printf("authenticateBasic: Authentication successful for user ID %d (%s)", user.ID, username)
	return user
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
