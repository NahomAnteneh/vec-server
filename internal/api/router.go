package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/NahomAnteneh/vec-server/internal/api/handlers"
	vecmiddleware "github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/protocol"
	"github.com/NahomAnteneh/vec-server/internal/repository"
	"gorm.io/gorm"
)

// SetupRouter configures the HTTP router for the API
func SetupRouter(cfg *config.Config, repoManager *repository.Manager, db *gorm.DB) http.Handler {
	r := chi.NewRouter()

	// Standard middleware
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(vecmiddleware.Logging())
	r.Use(vecmiddleware.RequestIDMiddleware())

	// CORS configuration
	cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum cache age for preflight options request
	})
	r.Use(cors.Handler)

	// Authentication middleware
	r.Use(vecmiddleware.AuthenticationMiddleware(cfg, db))

	// Create services
	userService := models.NewUserService(db)
	repoService := models.NewRepositoryService(db)
	permService := models.NewPermissionService(db)

	// API v1 routes (versioned API) for repositories only
	r.Route("/", func(r chi.Router) {
		// Repository listing - no specific user
		r.Get("/repos", handlers.ListUserRepositories(repoService))
		// Add a new POST route for creating repositories
		r.Post("/repos", handlers.CreateRepository(repoService))

		// Repository specific routes - direct username/repo pattern
		r.Route("/{username}/{repo}", func(r chi.Router) {
			// Repository middleware
			r.Use(createRepositoryMiddleware(db, repoManager))

			r.Get("/", handlers.GetRepository(repoService))
			r.Put("/", handlers.UpdateRepository(repoService))
			r.Delete("/", handlers.DeleteRepository(repoService))

			// Repository permissions
			r.Route("/permissions", func(r chi.Router) {
				r.Use(vecmiddleware.RequirePermission(models.AdminPermission))
				r.Get("/", handlers.ListCollaborators(repoService, permService))
				r.Post("/", handlers.AddCollaborator(userService, repoService, permService))
				r.Put("/{username}", handlers.UpdateCollaboratorPermissions(userService, repoService, permService))
				r.Delete("/{username}", handlers.RemoveCollaborator(userService, repoService, permService))
			})
		})
	})

	// Vec Smart HTTP protocol endpoints (non-versioned) with direct username/repo pattern
	// These must match exactly what the client expects
	r.Route("/{username}/{repo}", func(r chi.Router) {
		r.Use(createRepositoryMiddleware(db, repoManager))

		// Info/refs endpoint
		r.Get("/info/refs", protocol.InfoRefsHandler(repoManager))

		// Upload-pack endpoint (fetch)
		r.With(vecmiddleware.RequirePermission(models.ReadPermission)).
			Post("/vec-upload-pack", protocol.UploadPackHandler(repoManager))

		// Receive-pack endpoint (push)
		r.With(vecmiddleware.RequirePermission(models.WritePermission)).
			Post("/vec-receive-pack", protocol.ReceivePackHandler(repoManager))
	})

	return r
}

// createRepositoryMiddleware creates repository context middleware that loads the repository
// from the database and adds it to the request context
func createRepositoryMiddleware(db *gorm.DB, repoManager *repository.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get owner and repo name from URL
			username := chi.URLParam(r, "username")
			repoName := chi.URLParam(r, "repo")

			if username == "" || repoName == "" {
				http.Error(w, "Invalid repository path", http.StatusBadRequest)
				return
			}

			// Get repository from database
			repoService := models.NewRepositoryService(db)
			repo, err := repoService.GetByUsername(username, repoName)
			if err != nil {
				http.Error(w, "Repository not found", http.StatusNotFound)
				return
			}

			// Set repository path in the model if it's not already set
			if repo.Path == "" {
				repo.Path = repoManager.GetRepoPath(username, repoName)
				if err := repoService.Update(repo); err != nil {
					http.Error(w, "Failed to update repository path", http.StatusInternalServerError)
					return
				}
			}

			// Get user from repository
			userService := models.NewUserService(db)
			owner, err := userService.GetByID(repo.OwnerID)
			if err != nil {
				http.Error(w, "Failed to get repository owner", http.StatusInternalServerError)
				return
			}

			// Ensure repository exists on disk
			if err := repoManager.SyncRepository(repo, owner); err != nil {
				http.Error(w, "Failed to sync repository: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Create repository context
			repoContext := &vecmiddleware.RepositoryContext{
				Repository: repo,
				DB:         db,
			}

			// Add repository context to request context
			ctx := r.Context()
			ctx = context.WithValue(ctx, vecmiddleware.RepositoryContextKey, repoContext)

			// Continue with the next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
