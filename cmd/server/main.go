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
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

func main() {
	log.Println("Starting Vec server...")

	// Load configuration
	cfg := config.LoadConfig()

	// Ensure repository base path exists
	if err := os.MkdirAll(cfg.RepoBasePath, 0755); err != nil {
		log.Fatalf("Failed to create repository base path: %v", err)
	}

	// Connect to database
	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Verify database connection
	sqlDB, err := database.DB()
	if err != nil {
		log.Fatalf("Failed to get database connection: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}
	log.Println("Connected to database")

	// Run database migrations
	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}
	log.Println("Database migrations completed successfully")

	// Create repository manager
	repoManager := repository.NewManager(cfg)

	// Create router
	router := api.SetupRouter(cfg, repoManager, database)

	// Configure HTTP server with timeouts that match client expectations (60s default)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      router,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Increasing header limit for large packfile transfers
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start server in a goroutine so it doesn't block
	go func() {
		log.Printf("Vec server listening on port %d", cfg.ServerPort)
		if cfg.IsTLSEnabled() {
			log.Println("TLS enabled, starting HTTPS server")
			if err := server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("ListenAndServeTLS failed: %v", err)
			}
		} else {
			log.Println("TLS disabled, starting HTTP server")
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("ListenAndServe failed: %v", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	// Close database connection
	if err := sqlDB.Close(); err != nil {
		log.Fatalf("Failed to close database connection: %v", err)
	}

	log.Println("Server shutdown complete")
}
