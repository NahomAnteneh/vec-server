package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NahomAnteneh/vec-server/internal/api"
	"github.com/NahomAnteneh/vec-server/internal/config"
	"github.com/NahomAnteneh/vec-server/internal/db"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

func main() {
	// Initialize logger with prefix and timestamps
	logger := log.New(os.Stdout, "vec-server: ", log.LstdFlags)
	logger.Println("Starting Vec Repository Server...")
	logger.Println("This server provides repository hosting for the Vec version control system")
	logger.Println("Core functionality: repository discovery, clone/fetch, and push operations")

	// Load configuration
	cfg := config.LoadConfig()

	// Ensure repository base path exists
	if err := os.MkdirAll(cfg.RepoBasePath, cfg.RepoDirPerms); err != nil {
		logger.Fatalf("Failed to create repository base path %s: %v", cfg.RepoBasePath, err)
	}
	logger.Printf("Repository storage location: %s", cfg.RepoBasePath)

	// Connect to database
	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if sqlDB, err := database.DB(); err == nil {
			if err := sqlDB.Close(); err != nil {
				logger.Printf("Failed to close database connection: %v", err)
			}
		}
	}()

	// Verify database connection
	sqlDB, err := database.DB()
	if err != nil {
		logger.Fatalf("Failed to get database connection: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		logger.Fatalf("Database ping failed: %v", err)
	}
	logger.Println("Connected to database")

	// Run database migrations
	if err := db.RunMigrations(database); err != nil {
		logger.Fatalf("Failed to run database migrations: %v", err)
	}
	logger.Println("Database migrations completed successfully")

	// Initialize services
	commitService := models.NewCommitService(database)
	branchService := models.NewBranchService(database)
	logger.Println("Database services initialized")

	// Create repository manager
	repoManager := repository.NewManager(cfg, logger)

	// Create and set up sync manager
	syncManager := repository.NewSyncManager(repoManager, commitService, branchService)
	repoManager.SetSyncManager(syncManager)
	logger.Println("Repository manager and sync manager initialized")

	// Create router - focused on repository operations only
	router := api.SetupRouter(cfg, repoManager, database)
	logger.Println("Router configured for Vec repository operations")
	logger.Println("Endpoints: /{username}/{repo}/info/refs")
	logger.Println("           /{username}/{repo}/vec-upload-pack")
	logger.Println("           /{username}/{repo}/vec-receive-pack")

	// Configure HTTP server with timeouts
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:        router,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Channel to capture server errors
	serverErr := make(chan error, 1)

	// Start server in a goroutine
	go func() {
		logger.Printf("Vec Repository Server listening on port %d", cfg.ServerPort)
		if cfg.IsTLSEnabled() {
			logger.Println("TLS enabled, starting HTTPS server")
			serverErr <- server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
		} else {
			logger.Println("TLS disabled, starting HTTP server")
			serverErr <- server.ListenAndServe()
		}
	}()

	// Wait for interrupt signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed: %v", err)
		}
	case sig := <-quit:
		logger.Printf("Received signal: %v", sig)
		if sig == syscall.SIGHUP {
			logger.Println("SIGHUP received, ignoring (config reload not implemented)")
			// Add config reload logic here if needed
			return
		}
	}

	logger.Println("Shutting down server...")

	// Create context with configurable shutdown timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Println("Repository server shutdown complete")
}
