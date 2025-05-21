package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	vecmiddleware "github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// SetupRouter configures the HTTP router for the API
func SetupRouter(cfg *config.Config, repoManager *repository.Manager) http.Handler {
	r := chi.NewRouter()

	// Standard middleware
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

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
	r.Use(vecmiddleware.AuthenticationMiddleware(cfg))

	// API routes
	r.Route("/api", func(r chi.Router) {
		// User management
		r.Route("/users", func(r chi.Router) {
			r.Post("/", CreateUserHandler())
			r.Get("/", ListUsersHandler())

			r.Route("/{username}", func(r chi.Router) {
				r.Get("/", GetUserHandler())
				r.Put("/", UpdateUserHandler())
				r.Delete("/", DeleteUserHandler())

				// User tokens
				r.Route("/tokens", func(r chi.Router) {
					r.Get("/", GetUserTokensHandler())
					r.Post("/", CreateUserTokenHandler())
					r.Delete("/{token_id}", DeleteUserTokenHandler())
				})
			})
		})

		// Repository management
		r.Route("/repos", func(r chi.Router) {
			r.Post("/", CreateRepositoryHandler(repoManager))
			r.Get("/", ListRepositoriesHandler())

			// Repository specific routes
			r.Route("/{owner}/{repo}", func(r chi.Router) {
				// Repository middleware
				r.Use(vecmiddleware.RepositoryMiddleware)

				r.Get("/", GetRepositoryHandler())
				r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
					DeleteRepositoryHandler(repoManager)(w, r)
				})

				// Repository permissions
				r.Route("/permissions", func(r chi.Router) {
					r.Use(func(next http.Handler) http.Handler {
						return vecmiddleware.RequirePermission(models.AdminPermission)(next)
					})
					r.Get("/", GetRepositoryPermissionsHandler())
					r.Post("/", AddRepositoryPermissionHandler())
					r.Put("/{username}", UpdateRepositoryPermissionHandler())
					r.Delete("/{username}", RemoveRepositoryPermissionHandler())
				})
			})
		})
	})

	// Vec Smart HTTP protocol endpoints
	r.Route("/repos/{owner}/{repo}", func(r chi.Router) {
		r.Use(vecmiddleware.RepositoryMiddleware)

		// Info/refs endpoint
		r.Get("/info/refs", InfoRefsHandler(repoManager))

		// Upload-pack endpoint (fetch)
		r.With(func(next http.Handler) http.Handler {
			return vecmiddleware.RequirePermission(models.ReadPermission)(next)
		}).Post("/vec-upload-pack", UploadPackHandler(repoManager))

		// Receive-pack endpoint (push)
		r.With(func(next http.Handler) http.Handler {
			return vecmiddleware.RequirePermission(models.WritePermission)(next)
		}).Post("/vec-receive-pack", ReceivePackHandler(repoManager))
	})

	return r
}

// Placeholder handlers - these would be implemented in separate files
func CreateUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func ListUsersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func GetUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func UpdateUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func DeleteUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func GetUserTokensHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func CreateUserTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func DeleteUserTokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func CreateRepositoryHandler(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func ListRepositoriesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func GetRepositoryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func DeleteRepositoryHandler(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func GetRepositoryPermissionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func AddRepositoryPermissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func UpdateRepositoryPermissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}

func RemoveRepositoryPermissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Not implemented yet"))
	}
}
