package core

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Scope defines configuration scope
type Scope int

const (
	ScopeLocal Scope = iota
	ScopeGlobal
	ScopeSystem
)

// Config represents a Vec configuration
type Config struct {
	Remotes  map[string]*RemoteConfig
	Sections map[string]map[string][]string
	path     string
}

// RemoteConfig holds remote configuration
type RemoteConfig struct {
	URL     string
	Headers map[string]string
}

// NewConfig creates a new Config
func NewConfig() *Config {
	return &Config{
		Remotes:  make(map[string]*RemoteConfig),
		Sections: make(map[string]map[string][]string),
	}
}

// LoadConfig loads configuration, prioritizing local if repo is provided
func LoadConfig(repo *Repository) (*Config, error) {
	cfg := NewConfig()
	var path string

	// Try local config if repo is provided
	if repo != nil {
		path = filepath.Join(repo.Root, VecDirName, "config")
		cfg.path = path
		loadedCfg, err := loadConfigFile(cfg, path)
		if err != nil {
			return nil, err
		}
		if len(loadedCfg.Sections) > 0 {
			return loadedCfg, nil
		}
	}

	// Fall back to global config
	homeDir, err := GetUserHomeDir()
	if err != nil {
		return nil, FSError("failed to get home directory", err)
	}
	path = filepath.Join(homeDir, ".vecconfig")
	cfg.path = path
	return loadConfigFile(cfg, path)
}

// loadConfigFile loads a configuration file
func loadConfigFile(cfg *Config, path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, FSError(fmt.Sprintf("failed to stat config file %s", path), err)
	}
	if info.IsDir() {
		return cfg, nil // Treat directory as non-existent config
	}
	file, err := OpenFile(path)
	if err != nil {
		return nil, FSError(fmt.Sprintf("failed to open config file %s", path), err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentSection string
	sectionRe := regexp.MustCompile(`^\s*\[([^\]]*)\]\s*$`)
	keyValueRe := regexp.MustCompile(`^\s*([^=]+)\s*=\s*(.*)\s*$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if sectionMatch := sectionRe.FindStringSubmatch(line); sectionMatch != nil {
			currentSection = sectionMatch[1]
			if _, exists := cfg.Sections[currentSection]; !exists {
				cfg.Sections[currentSection] = make(map[string][]string)
			}
			continue
		}
		if kvMatch := keyValueRe.FindStringSubmatch(line); kvMatch != nil && currentSection != "" {
			key := strings.TrimSpace(kvMatch[1])
			value := strings.TrimSpace(kvMatch[2])
			cfg.Sections[currentSection][key] = append(cfg.Sections[currentSection][key], value)
			if strings.HasPrefix(currentSection, "remote.") {
				remoteName := strings.Trim(strings.TrimPrefix(currentSection, "remote."), "\"")
				if _, exists := cfg.Remotes[remoteName]; !exists {
					cfg.Remotes[remoteName] = &RemoteConfig{
						Headers: make(map[string]string),
					}
				}
				if key == "url" {
					cfg.Remotes[remoteName].URL = value
				} else if strings.HasPrefix(key, "header.") {
					headerKey := strings.TrimPrefix(key, "header.")
					cfg.Remotes[remoteName].Headers[headerKey] = value
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, FSError(fmt.Sprintf("failed to read config file %s", path), err)
	}
	return cfg, nil
}

// GetRemoteURL gets the URL for a remote
func (c *Config) GetRemoteURL(remoteName string) (string, error) {
	remote, exists := c.Remotes[remoteName]
	if !exists {
		return "", fmt.Errorf("remote '%s' not found", remoteName)
	}
	if remote.URL == "" {
		return "", fmt.Errorf("no URL configured for remote '%s'", remoteName)
	}
	return remote.URL, nil
}

// GetRemoteHeaders gets custom headers for a remote
func (c *Config) GetRemoteHeaders(remoteName string) (map[string]string, error) {
	remote, exists := c.Remotes[remoteName]
	if !exists {
		return nil, fmt.Errorf("remote '%s' not found", remoteName)
	}
	return remote.Headers, nil
}

// GetConfigValue gets a configuration value
func GetConfigValue(repo *Repository, key string) (string, error) {
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid config key: %s", key)
	}
	section := strings.Join(parts[:len(parts)-1], ".")
	name := parts[len(parts)-1]

	cfg, err := LoadConfig(repo)
	if err != nil {
		return "", err
	}
	if values, exists := cfg.Sections[section][name]; exists && len(values) > 0 {
		return values[0], nil
	}
	return "", nil
}

// GetConfigValues gets all configuration values for a key
func GetConfigValues(repo *Repository, key string) ([]string, error) {
	cfg, err := LoadConfig(repo)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid config key: %s", key)
	}
	section := strings.Join(parts[:len(parts)-1], ".")
	name := parts[len(parts)-1]
	if values, exists := cfg.Sections[section][name]; exists {
		return values, nil
	}
	return nil, nil
}

// SetConfigValue sets a configuration value
func SetConfigValue(repo *Repository, key, value string, scope Scope) error {
	cfg, err := loadConfigForScope(repo, scope)
	if err != nil {
		return err
	}
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid config key: %s", key)
	}
	section := strings.Join(parts[:len(parts)-1], ".")
	name := parts[len(parts)-1]
	if _, exists := cfg.Sections[section]; !exists {
		cfg.Sections[section] = make(map[string][]string)
	}
	cfg.Sections[section][name] = []string{value}
	if strings.HasPrefix(section, "remote.") {
		remoteName := strings.Trim(strings.TrimPrefix(section, "remote."), "\"")
		if _, exists := cfg.Remotes[remoteName]; !exists {
			cfg.Remotes[remoteName] = &RemoteConfig{Headers: make(map[string]string)}
		}
		if name == "url" {
			cfg.Remotes[remoteName].URL = value
		} else if strings.HasPrefix(name, "header.") {
			headerKey := strings.TrimPrefix(name, "header.")
			cfg.Remotes[remoteName].Headers[headerKey] = value
		}
	}
	return cfg.Write()
}

// AddConfigValue adds a configuration value to a key
func AddConfigValue(repo *Repository, key, value string, scope Scope) error {
	cfg, err := loadConfigForScope(repo, scope)
	if err != nil {
		return err
	}
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid config key: %s", key)
	}
	section := strings.Join(parts[:len(parts)-1], ".")
	name := parts[len(parts)-1]
	if _, exists := cfg.Sections[section]; !exists {
		cfg.Sections[section] = make(map[string][]string)
	}
	cfg.Sections[section][name] = append(cfg.Sections[section][name], value)
	if strings.HasPrefix(section, "remote.") {
		remoteName := strings.Trim(strings.TrimPrefix(section, "remote."), "\"")
		if _, exists := cfg.Remotes[remoteName]; !exists {
			cfg.Remotes[remoteName] = &RemoteConfig{Headers: make(map[string]string)}
		}
		if name == "url" {
			cfg.Remotes[remoteName].URL = value
		} else if strings.HasPrefix(name, "header.") {
			headerKey := strings.TrimPrefix(name, "header.")
			cfg.Remotes[remoteName].Headers[headerKey] = value
		}
	}
	return cfg.Write()
}

// UnsetConfigValue removes a configuration value
func UnsetConfigValue(repo *Repository, key, value string, scope Scope) error {
	cfg, err := loadConfigForScope(repo, scope)
	if err != nil {
		return err
	}
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid config key: %s", key)
	}
	section := strings.Join(parts[:len(parts)-1], ".")
	name := parts[len(parts)-1]
	if _, exists := cfg.Sections[section]; exists {
		if values, exists := cfg.Sections[section][name]; exists {
			if value != "" {
				newValues := []string{}
				for _, v := range values {
					if v != value {
						newValues = append(newValues, v)
					}
				}
				if len(newValues) > 0 {
					cfg.Sections[section][name] = newValues
				} else {
					delete(cfg.Sections[section], name)
				}
			} else {
				delete(cfg.Sections[section], name)
			}
		}
		if len(cfg.Sections[section]) == 0 {
			delete(cfg.Sections, section)
		}
	}

	if strings.HasPrefix(section, "remote.") {
		remoteName := strings.Trim(strings.TrimPrefix(section, "remote."), "\"")
		if name == "url" && value == "" {
			if _, exists := cfg.Remotes[remoteName]; exists {
				cfg.Remotes[remoteName].URL = ""
			}
		} else if strings.HasPrefix(name, "header.") && value == "" {
			headerKey := strings.TrimPrefix(name, "header.")
			if remote, exists := cfg.Remotes[remoteName]; exists {
				delete(remote.Headers, headerKey)
			}
		}
	}

	return cfg.Write()
}

// ListConfig lists all configuration settings
func ListConfig(repo *Repository) (map[string][]string, error) {
	cfg, err := LoadConfig(repo)
	if err != nil {
		return nil, err
	}
	if len(cfg.Sections) == 0 {
		return nil, nil
	}
	return convertConfigToMap(cfg), nil
}

// EditConfig opens the configuration file in the default editor
func EditConfig(repo *Repository, scope Scope) error {
	var configPath string
	var err error
	switch scope {
	case ScopeLocal:
		if repo == nil {
			repoRoot, err := GetVecRoot()
			if err != nil {
				return err
			}
			repo = NewRepository(repoRoot)
		}
		configPath = filepath.Join(repo.Root, VecDirName, "config")
	case ScopeGlobal:
		configPath, err = GetGlobalConfigPath()
		if err != nil {
			return err
		}
	case ScopeSystem:
		configPath = "/etc/vecconfig"
	default:
		return fmt.Errorf("invalid scope: %v", scope)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	execCmd := exec.Command(editor, configPath)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	return execCmd.Run()
}

// loadConfigForScope loads config for a scope
func loadConfigForScope(repo *Repository, scope Scope) (*Config, error) {
	cfg := NewConfig()
	var path string
	switch scope {
	case ScopeLocal:
		if repo == nil {
			repoRoot, err := GetVecRoot()
			if err != nil {
				return nil, RepositoryError("not a vec repository", err)
			}
			repo = NewRepository(repoRoot)
		}
		path = filepath.Join(repo.Root, VecDirName, "config")
	case ScopeGlobal:
		homeDir, err := GetUserHomeDir()
		if err != nil {
			return nil, FSError("failed to get home directory", err)
		}
		path = filepath.Join(homeDir, ".vecconfig")
	case ScopeSystem:
		path = "/etc/vecconfig"
	default:
		return nil, fmt.Errorf("invalid scope: %d", scope)
	}
	cfg.path = path
	return loadConfigFile(cfg, path)
}

// Write saves the configuration to file
func (c *Config) Write() error {
	if c.path == "" {
		return fmt.Errorf("no config file path specified")
	}
	configDir := filepath.Dir(c.path)
	if err := EnsureDirExists(configDir); err != nil {
		return FSError(fmt.Sprintf("failed to create config directory %s", configDir), err)
	}
	// If path is a directory, remove it to ensure we write a file
	if info, err := os.Stat(c.path); err == nil && info.IsDir() {
		if err := os.RemoveAll(c.path); err != nil {
			return FSError(fmt.Sprintf("failed to remove directory at %s", c.path), err)
		}
	}
	var content strings.Builder
	for section, keys := range c.Sections {
		fmt.Fprintf(&content, "[%s]\n", section)
		for key, values := range keys {
			for _, value := range values {
				fmt.Fprintf(&content, "\t%s = %s\n", key, value)
			}
		}
		fmt.Fprintln(&content)
	}
	return WriteFileContent(c.path, []byte(content.String()), 0644)
}

// GetGlobalConfigPath returns the path to the global configuration file
func GetGlobalConfigPath() (string, error) {
	homeDir, err := GetUserHomeDir()
	if err != nil {
		return "", FSError("failed to get home directory", err)
	}
	return filepath.Join(homeDir, ".vecconfig"), nil
}

// ReadConfig reads a configuration file and returns a flat key-value map
func ReadConfig(filePath string) (map[string]string, error) {
	cfg := NewConfig()
	cfg, err := loadConfigFile(cfg, filePath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for section, keys := range cfg.Sections {
		for key, values := range keys {
			if len(values) > 0 {
				result[section+"."+key] = values[0]
			}
		}
	}

	return result, nil
}

// WriteConfig writes a flat key-value map to a configuration file
func WriteConfig(filePath string, config map[string]string) error {
	cfg := NewConfig()
	cfg.path = filePath

	for fullKey, value := range config {
		parts := strings.Split(fullKey, ".")
		if len(parts) < 2 {
			continue
		}

		section := strings.Join(parts[:len(parts)-1], ".")
		key := parts[len(parts)-1]

		if _, exists := cfg.Sections[section]; !exists {
			cfg.Sections[section] = make(map[string][]string)
		}

		cfg.Sections[section][key] = []string{value}

		if strings.HasPrefix(section, "remote.") {
			remoteName := strings.Trim(strings.TrimPrefix(section, "remote."), "\"")
			if _, exists := cfg.Remotes[remoteName]; !exists {
				cfg.Remotes[remoteName] = &RemoteConfig{Headers: make(map[string]string)}
			}
			if key == "url" {
				cfg.Remotes[remoteName].URL = value
			} else if strings.HasPrefix(key, "header.") {
				headerKey := strings.TrimPrefix(key, "header.")
				cfg.Remotes[remoteName].Headers[headerKey] = value
			}
		}
	}

	return cfg.Write()
}

// convertConfigToMap converts a Config to a map for listing
func convertConfigToMap(cfg *Config) map[string][]string {
	result := make(map[string][]string)
	for section, keys := range cfg.Sections {
		for key, values := range keys {
			result[section+"."+key] = values
		}
	}
	return result
}
