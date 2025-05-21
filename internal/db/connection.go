package db

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Connect creates a connection to the database using the provided URL
func Connect(databaseURL string) (*gorm.DB, error) {
	// Configure GORM logger
	gormLogger := logger.New(
		log.New(log.Writer(), "[DB] ", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// Open connection
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger: gormLogger,
	})

	if err != nil {
		return nil, err
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool
	sqlDB.SetMaxIdleConns(10)

	// SetMaxOpenConns sets the maximum number of open connections to the database
	sqlDB.SetMaxOpenConns(100)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigrateSchema runs all database migrations
func MigrateSchema(db *gorm.DB) error {
	// Add models to migrate here
	// Example: return db.AutoMigrate(&models.User{}, &models.Repository{}, &models.Permission{})

	// Migration is not yet implemented
	return nil
}

// RunMigrations runs all SQL migrations in the migrations directory
func RunMigrations(db *gorm.DB) error {
	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(sqlDB); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get list of applied migrations
	appliedMigrations, err := getAppliedMigrations(sqlDB)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get migration files
	migrationFiles, err := getMigrationFiles()
	if err != nil {
		return fmt.Errorf("failed to get migration files: %w", err)
	}

	// Apply migrations
	for _, file := range migrationFiles {
		// Skip if already applied
		if contains(appliedMigrations, file) {
			log.Printf("Migration %s already applied, skipping", file)
			continue
		}

		log.Printf("Applying migration: %s", file)

		// Read migration file
		content, err := ioutil.ReadFile(filepath.Join("internal/db/migrations", file))
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		// Extract Up section
		upSQL := extractUpSection(string(content))
		if upSQL == "" {
			return fmt.Errorf("no Up section found in migration file %s", file)
		}

		// Begin transaction
		tx, err := sqlDB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %s: %w", file, err)
		}

		// Execute migration
		if _, err := tx.Exec(upSQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}

		// Record migration
		if _, err := tx.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, NOW())", file); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", file, err)
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", file, err)
		}

		log.Printf("Successfully applied migration: %s", file)
	}

	return nil
}

// createMigrationsTable creates the schema_migrations table if it doesn't exist
func createMigrationsTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL
		)
	`
	_, err := db.Exec(query)
	return err
}

// getAppliedMigrations returns a list of already applied migrations
func getAppliedMigrations(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return versions, nil
}

// getMigrationFiles returns a sorted list of migration files
func getMigrationFiles() ([]string, error) {
	files, err := ioutil.ReadDir("internal/db/migrations")
	if err != nil {
		return nil, err
	}

	var migrations []string
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".sql" {
			migrations = append(migrations, file.Name())
		}
	}

	sort.Strings(migrations)
	return migrations, nil
}

// extractUpSection extracts the SQL in the Up section of a migration file
func extractUpSection(content string) string {
	upMarker := "-- +migrate Up"
	downMarker := "-- +migrate Down"

	upIndex := strings.Index(content, upMarker)
	if upIndex == -1 {
		return ""
	}

	upIndex += len(upMarker)

	downIndex := strings.Index(content, downMarker)
	if downIndex == -1 {
		return strings.TrimSpace(content[upIndex:])
	}

	return strings.TrimSpace(content[upIndex:downIndex])
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
