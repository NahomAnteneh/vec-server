package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	CustomHeaderName string
	CustomHeaderType string // "username" or "token"
}

// Config holds all application configuration
type Config struct {
	// Server configuration
	ServerPort      int
	RepoBasePath    string
	RepoDirPerms    os.FileMode
	ShutdownTimeout time.Duration

	// Database configuration
	DatabaseURL string

	// TLS configuration
	TLSCertPath string
	TLSKeyPath  string

	// JWT configuration
	JWTSecret string

	// Authentication configuration
	Auth AuthConfig

	// CORS configuration
	CORS CORSConfig
}

// IsTLSEnabled returns true if TLS is enabled
func (c *Config) IsTLSEnabled() bool {
	return c.TLSCertPath != "" && c.TLSKeyPath != ""
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	corsOrigins := getEnvStr("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	origins := []string{}
	for _, o := range splitAndTrim(corsOrigins, ",") {
		if o != "" {
			origins = append(origins, o)
		}
	}

	cfg := &Config{
		ServerPort:      getEnvInt("SERVER_PORT", 8080),
		RepoBasePath:    getEnvStr("REPO_BASE_PATH", "./repos"),
		RepoDirPerms:    getEnvFileMode("REPO_DIR_PERMS", 0755),
		ShutdownTimeout: getEnvDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
		DatabaseURL:     getEnvStr("DATABASE_URL", "postgresql://neondb_owner:npg_8OKrybDhPx5T@ep-lucky-waterfall-a51p4m44-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"),
		TLSCertPath:     getEnvStr("TLS_CERT_PATH", ""),
		TLSKeyPath:      getEnvStr("TLS_KEY_PATH", ""),
		JWTSecret:       getEnvStr("JWT_SECRET", "vec-server-default-secret-key"),
		Auth: AuthConfig{
			CustomHeaderName: getEnvStr("AUTH_CUSTOM_HEADER_NAME", ""),
			CustomHeaderType: getEnvStr("AUTH_CUSTOM_HEADER_TYPE", "username"),
		},
		CORS: CORSConfig{
			AllowedOrigins: origins,
		},
	}

	log.Printf("Server configuration: port=%d, repo_path=%s, repo_perms=%#o, shutdown_timeout=%s",
		cfg.ServerPort, cfg.RepoBasePath, cfg.RepoDirPerms, cfg.ShutdownTimeout)

	return cfg
}

// getEnvStr retrieves an environment variable or returns a default value
func getEnvStr(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultVal
}

// getEnvInt retrieves an environment variable as an integer or returns a default value
func getEnvInt(key string, defaultVal int) int {
	if val, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
		log.Printf("Warning: invalid value for %s, using default: %d", key, defaultVal)
	}
	return defaultVal
}

// getEnvFileMode retrieves an environment variable as an os.FileMode or returns a default value
func getEnvFileMode(key string, defaultVal os.FileMode) os.FileMode {
	if val, exists := os.LookupEnv(key); exists {
		// Parse as octal (e.g., "0755")
		if mode, err := strconv.ParseInt(val, 8, 32); err == nil {
			return os.FileMode(mode)
		}
		log.Printf("Warning: invalid value for %s, using default: %#o", key, defaultVal)
	}
	return defaultVal
}

// getEnvDuration retrieves an environment variable as a time.Duration or returns a default value
func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, exists := os.LookupEnv(key); exists {
		if dur, err := time.ParseDuration(val); err == nil {
			return dur
		}
		log.Printf("Warning: invalid value for %s, using default: %s", key, defaultVal)
	}
	return defaultVal
}

// splitAndTrim splits a string by sep and trims spaces from each element
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
