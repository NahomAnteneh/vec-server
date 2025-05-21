package config

import (
	"log"
	"os"
	"strconv"
)

// Config holds all application configuration
type Config struct {
	// Server configuration
	ServerPort   int
	RepoBasePath string

	// Database configuration
	DatabaseURL string

	// TLS configuration
	TLSCertPath string
	TLSKeyPath  string

	// JWT configuration
	JWTSecret string
}

// IsTLSEnabled returns true if TLS is enabled
func (c *Config) IsTLSEnabled() bool {
	return c.TLSCertPath != "" && c.TLSKeyPath != ""
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	cfg := &Config{
		ServerPort:   getEnvInt("SERVER_PORT", 8080),
		RepoBasePath: getEnvStr("REPO_BASE_PATH", "./repos"),
		DatabaseURL:  getEnvStr("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/vecserver?sslmode=disable"),
		TLSCertPath:  getEnvStr("TLS_CERT_PATH", ""),
		TLSKeyPath:   getEnvStr("TLS_KEY_PATH", ""),
		JWTSecret:    getEnvStr("JWT_SECRET", "vec-server-default-secret-key"),
	}

	log.Printf("Server configuration: port=%d, repo_path=%s", cfg.ServerPort, cfg.RepoBasePath)

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
