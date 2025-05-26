package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"

	"github.com/NahomAnteneh/vec-server/internal/api/handlers"
	"github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/protocol"
	"github.com/NahomAnteneh/vec-server/internal/repository"
	"gorm.io/gorm"
)

// SetupRouter configures the HTTP router for the API
func SetupRouter(cfg *config.Config, repoManager *repository.Manager, db *gorm.DB) http.Handler {
	logger := log.New(os.Stdout, "vec-server: ", log.LstdFlags)
	r := chi.NewRouter()

	// Standard middleware
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.Logging())
	r.Use(middleware.ErrorLogMiddleware())
	r.Use(chimiddleware.Compress(5))               // Enable compression (level 5)
	r.Use(chimiddleware.Timeout(30 * time.Second)) // 30s timeout
	r.Use(chimiddleware.Throttle(100))             // 100 requests per minute

	// CORS configuration
	corsOrigins := cfg.CORS.AllowedOrigins
	if len(corsOrigins) == 0 {
		corsOrigins = []string{"http://localhost:3000"} // Default for dev
	}
	cors := cors.New(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	r.Use(cors.Handler)

	// Create services
	userService := models.NewUserService(db)
	repoService := models.NewRepositoryService(db)
	permService := models.NewPermissionService(db)

	// Add services and repoManager to context
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "userService", userService)
			ctx = context.WithValue(ctx, "repoService", repoService)
			ctx = context.WithValue(ctx, "permissionService", permService)
			ctx = context.WithValue(ctx, "repoManager", repoManager)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Authorization function for protocol handlers
	authorize := func(r *http.Request, repo *models.Repository) error {
		ctx := r.Context()
		repoCtx, ok := ctx.Value(middleware.RepositoryContextKey).(*middleware.RepositoryContext)
		if !ok || repoCtx.Repository == nil {
			return fmt.Errorf("repository context not found")
		}

		// For public repositories and read operations (vec-upload-pack), allow access without authentication
		permLevel := models.ReadPermission
		if r.Method == http.MethodPost && r.URL.Path == "/"+repoCtx.Repository.Owner.Username+"/"+repoCtx.Repository.Name+"/vec-receive-pack" {
			permLevel = models.WritePermission
		}

		// Allow public repositories to be cloned without authentication
		if permLevel == models.ReadPermission && repoCtx.Repository.IsPublic {
			return nil
		}

		user := auth.GetUserFromContext(ctx)
		if user == nil {
			return fmt.Errorf("user not authenticated")
		}

		permService := ctx.Value("permissionService").(models.PermissionService)
		hasPermission, err := permService.HasPermission(user.ID, repoCtx.Repository.ID, permLevel)
		if err != nil || !hasPermission {
			return fmt.Errorf("permission denied")
		}
		return nil
	}

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, map[string]string{"status": "ok"})
	})

	// User repositories
	r.Get("/users/{username}/repos", handlers.ListUserRepositories(repoService))

	// Repository management
	r.With(middleware.AuthenticationMiddleware(cfg, db)).
		Post("/create", handlers.CreateRepository(repoService))

	// Repository CRUD operations and Vec Protocol endpoints
	r.Route("/{username}/{repo}", func(r chi.Router) {
		r.Use(createRepositoryMiddleware(db, repoManager))

		// General repository info
		r.Get("/", handlers.GetRepository(repoService))

		// Update/Delete operations (require authentication)
		r.With(middleware.AuthenticationMiddleware(cfg, db)).
			Put("/", handlers.UpdateRepository(repoService))
		r.With(middleware.AuthenticationMiddleware(cfg, db)).
			Delete("/", handlers.DeleteRepository(repoService))
		r.With(middleware.AuthenticationMiddleware(cfg, db)).
			Post("/fork", handlers.ForkRepository(repoService))

		// Repository content information
		r.Get("/branches", handlers.ListBranches(repoManager))
		r.Get("/branches/{branch}", handlers.GetBranch(repoManager))
		r.Get("/commits", handlers.ListCommits(repoManager))
		r.Get("/commits/{commit}", handlers.GetCommit(repoManager))
		r.Get("/tree/{ref}", handlers.GetTreeContents(repoManager))
		r.Get("/tree/{ref}/{path:.+}", handlers.GetTreeContents(repoManager))
		r.Get("/blob/{ref}/{path:.+}", handlers.GetBlob(repoManager))

		// Vec Protocol endpoints
		r.Get("/info/refs", protocol.InfoRefsHandler(repoManager, logger))

		// Upload-pack (fetch/clone) - allows public access for public repositories
		r.Post("/vec-upload-pack", protocol.UploadPackHandler(repoManager, logger, authorize))

		// Receive-pack (push) - requires write permission
		r.With(middleware.AuthenticationMiddleware(cfg, db)).
			With(middleware.RequirePermission(models.WritePermission)).
			Post("/vec-receive-pack", protocol.ReceivePackHandler(repoManager, logger, authorize))
	})

	return r
}

// createRepositoryMiddleware creates repository context middleware
func createRepositoryMiddleware(db *gorm.DB, repoManager *repository.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username := chi.URLParam(r, "username")
			repoName := chi.URLParam(r, "repo")

			if username == "" || repoName == "" {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, map[string]string{"error": "Invalid repository path"})
				return
			}

			// Retrieve services from context
			repoService, ok := r.Context().Value("repoService").(models.RepositoryService)
			if !ok {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "Repository service not found"})
				return
			}
			userService, ok := r.Context().Value("userService").(models.UserService)
			if !ok {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "User service not found"})
				return
			}

			repo, err := repoService.GetByUsername(username, repoName)
			if err != nil {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, map[string]string{"error": "Repository not found"})
				return
			}

			repoPath, err := repoManager.GetRepoPath(username, repoName)
			if err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, map[string]string{"error": "Invalid repository path: " + err.Error()})
				return
			}
			repo.Path = repoPath // Set Path for runtime use (not persisted)

			owner, err := userService.GetByID(repo.OwnerID)
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "Failed to get repository owner"})
				return
			}

			if err := repoManager.SyncRepository(repo, owner); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, map[string]string{"error": "Failed to sync repository: " + err.Error()})
				return
			}

			repoContext := &middleware.RepositoryContext{
				Repository: repo,
				DB:         db,
			}

			ctx := context.WithValue(r.Context(), middleware.RepositoryContextKey, repoContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
