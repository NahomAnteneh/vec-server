package core

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// GetGlobalConfigPath returns the path to the global configuration file.
func GetGlobalConfigPath() (string, error) {
	var homeDir string
	if runtime.GOOS == "windows" {
		homeDir = os.Getenv("USERPROFILE")
	} else {
		homeDir = os.Getenv("HOME")
	}

	if homeDir == "" {
		return "", fmt.Errorf("home directory not found")
	}
	return filepath.Join(homeDir, ".vecconfig"), nil
}

// ReadGlobalConfig reads the global configuration file.
func ReadGlobalConfig() (map[string]string, error) {
	configPath, err := GetGlobalConfigPath()
	if err != nil {
		return nil, err
	}
	return ReadConfig(configPath)
}

// WriteGlobalConfig writes the global configuration file.
func WriteGlobalConfig(config map[string]string) error {
	configPath, err := GetGlobalConfigPath()
	if err != nil {
		return err
	}
	return WriteConfig(configPath, config)
}

// ReadConfig reads a config file (either global or local).
func ReadConfig(filePath string) (map[string]string, error) {
	config := make(map[string]string)

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return empty map if not exist
		}
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty and comment lines
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" && value != "" { // Prevent empty key/value
			config[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return config, nil
}

// WriteConfig writes to a config file (either global or local)
func WriteConfig(filePath string, config map[string]string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, value := range config {
		_, err := fmt.Fprintf(writer, "%s = %s\n", key, value)
		if err != nil {
			return fmt.Errorf("failed to write to config file: %w", err)
		}
	}
	return writer.Flush()
}

// GetConfigValue gets a config value, checking local then global.
func GetConfigValue(repoRoot string, key string) (string, error) {
	// First, try to get the local config value.
	localConfig, err := ReadConfig(filepath.Join(repoRoot, VecDirName, "config"))
	if err != nil {
		return "", err
	}
	if value, ok := localConfig[key]; ok {
		return value, nil // Found in local config.
	}

	// If not found locally, try the global config
	globalConfig, err := ReadGlobalConfig()
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if value, ok := globalConfig[key]; ok {
		return value, nil // Found in global config.
	}

	// If not found in either, return an empty string and no error (it's optional).
	return "", nil
}

// SetConfigValue sets a config value (either local or global).
func SetConfigValue(repoRoot string, key string, value string, global bool) error {
	var configPath string
	var config map[string]string
	var err error

	if global {
		configPath, err = GetGlobalConfigPath()
		if err != nil {
			return err
		}
		config, err = ReadGlobalConfig()
	} else {
		configPath = filepath.Join(repoRoot, VecDirName, "config")
		config, err = ReadConfig(configPath)
	}

	if err != nil && !os.IsNotExist(err) {
		return err
	} else if os.IsNotExist(err) {
		config = make(map[string]string)
	}

	config[key] = value // Set new value

	if global {
		return WriteGlobalConfig(config)
	}
	return WriteConfig(configPath, config)
}

// UnsetConfigValue unsets (removes) a config value (either local or global).
func UnsetConfigValue(repoRoot string, key string, global bool) error {
	var configPath string
	var config map[string]string
	var err error

	if global {
		configPath, err = GetGlobalConfigPath()
		if err != nil {
			return err
		}
		config, err = ReadGlobalConfig()
	} else {
		configPath = filepath.Join(repoRoot, VecDirName, "config")
		config, err = ReadConfig(configPath)
	}

	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if _, ok := config[key]; !ok {
		return fmt.Errorf("config key '%s' not found", key)
	}

	delete(config, key)

	if global {
		return WriteGlobalConfig(config)
	}
	return WriteConfig(configPath, config)
}
