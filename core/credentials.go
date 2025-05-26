package core

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GetAuthToken retrieves the authentication token for a remote
func GetAuthToken(repo *Repository, remoteName string) (string, error) {
	if repo == nil {
		return "", RepositoryError("nil repository", nil)
	}

	// 1. Check credential helper
	helper, err := GetConfigValue(repo, "credential.helper")
	if err == nil && helper != "" {
		token, err := runCredentialHelperGet(helper, remoteName)
		if err == nil && token != "" {
			return token, nil
		}
	}

	// 2. Check environment variable VEC_CREDENTIALS
	if envCreds := os.Getenv("VEC_CREDENTIALS"); envCreds != "" {
		if parsed := parseVecCredential(envCreds, remoteName); parsed != "" {
			return parsed, nil
		}
	}

	// 3. Check ~/.vec/credentials
	homeDir, err := GetUserHomeDir()
	if err != nil {
		return "", FSError("failed to get home directory", err)
	}
	credsPath := filepath.Join(homeDir, ".vec", "credentials")
	if _, err := StatFile(credsPath); IsNotExist(err) {
		return "", nil
	}

	file, err := OpenFile(credsPath)
	if err != nil {
		return "", FSError("failed to open credentials file", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parsed := parseVecCredential(line, remoteName); parsed != "" {
			return parsed, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", FSError("failed to read credentials file", err)
	}
	return "", nil
}

// StoreAuthToken stores a token in ~/.vec/credentials
func StoreAuthToken(repo *Repository, remoteName, token string) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}

	// Check if credential helper is configured
	helper, err := GetConfigValue(repo, "credential.helper")
	if err == nil && helper != "" {
		return runCredentialHelper(helper, remoteName, "store", token)
	}

	homeDir, err := GetUserHomeDir()
	if err != nil {
		return FSError("failed to get home directory", err)
	}
	credsPath := filepath.Join(homeDir, ".vec", "credentials")
	credsDir := filepath.Dir(credsPath)
	if err := EnsureDirExists(credsDir); err != nil {
		return FSError("failed to create credentials directory", err)
	}

	// Use remoteName as the host in the credential line
	credLine := fmt.Sprintf("https://:%s@%s", token, remoteName)

	var content strings.Builder
	existing := make(map[string]bool)
	if _, err := StatFile(credsPath); !IsNotExist(err) {
		file, err := OpenFile(credsPath)
		if err != nil {
			return FSError("failed to open credentials file", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				fmt.Fprintf(&content, "%s\n", line)
				continue
			}
			if strings.Contains(line, remoteName) {
				continue
			}
			existing[line] = true
			fmt.Fprintf(&content, "%s\n", line)
		}
		if err := scanner.Err(); err != nil {
			return FSError("failed to read credentials file", err)
		}
	}
	if !existing[credLine] {
		fmt.Fprintf(&content, "%s\n", credLine)
	}
	return WriteFileContent(credsPath, []byte(content.String()), 0600)
}

// EraseAuthToken erases the credential for a remote
func EraseAuthToken(repo *Repository, remoteName string) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}

	// Check if credential helper is configured
	helper, err := GetConfigValue(repo, "credential.helper")
	if err == nil && helper != "" {
		return runCredentialHelper(helper, remoteName, "erase")
	}

	homeDir, err := GetUserHomeDir()
	if err != nil {
		return FSError("failed to get home directory", err)
	}
	credsPath := filepath.Join(homeDir, ".vec", "credentials")
	if _, err := StatFile(credsPath); IsNotExist(err) {
		return nil
	}

	var content strings.Builder
	changed := false
	file, err := OpenFile(credsPath)
	if err != nil {
		return FSError("failed to open credentials file", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			fmt.Fprintf(&content, "%s\n", line)
			continue
		}
		if strings.Contains(line, remoteName) {
			changed = true
			continue
		}
		fmt.Fprintf(&content, "%s\n", line)
	}
	if err := scanner.Err(); err != nil {
		return FSError("failed to read credentials file", err)
	}
	if !changed {
		return nil
	}
	return WriteFileContent(credsPath, []byte(content.String()), 0600)
}

// ValidateAuthToken validates the credential for a remote
func ValidateAuthToken(repo *Repository, remoteName string) error {
	if repo == nil {
		return RepositoryError("nil repository", nil)
	}
	token, err := GetAuthToken(repo, remoteName)
	if err != nil {
		return fmt.Errorf("failed to get credential: %w", err)
	}
	if token == "" {
		return fmt.Errorf("no credential found for remote '%s'", remoteName)
	}

	// Validate JWT format
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT token format")
	}

	// Check expiration
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		var claims map[string]interface{}
		if err := json.Unmarshal(payload, &claims); err == nil {
			if exp, ok := claims["exp"].(float64); ok {
				expTime := time.Unix(int64(exp), 0)
				if time.Now().After(expTime) {
					return fmt.Errorf("credential for remote '%s' has expired on %s",
						remoteName, expTime.Format(time.RFC1123))
				}
			}
		}
	}

	return nil
}

// InfoAuthToken shows information about a remote's credential
func InfoAuthToken(repo *Repository, remoteName string) (map[string]interface{}, error) {
	if repo == nil {
		return nil, RepositoryError("nil repository", nil)
	}
	token, err := GetAuthToken(repo, remoteName)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("no credential found for remote '%s'", remoteName)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return map[string]interface{}{"token": token}, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]interface{}{"token": token}, nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return map[string]interface{}{"token": token}, nil
	}

	claims["remote"] = remoteName
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		claims["expires"] = expTime.Format(time.RFC1123)
		claims["expired"] = time.Now().After(expTime)
	}
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt := time.Unix(int64(iat), 0)
		claims["issued_at"] = issuedAt.Format(time.RFC1123)
	}

	return claims, nil
}

// runCredentialHelper runs a credential helper with the specified operation
func runCredentialHelper(helper, remoteName, operation string, token ...string) error {
	parts := strings.Fields(helper)
	if len(parts) == 0 {
		return fmt.Errorf("invalid credential helper: %s", helper)
	}
	cmdName := "vec-credential-" + parts[0]
	args := append(parts[1:], operation)
	cmd := exec.Command(cmdName, args...)
	var input strings.Builder
	fmt.Fprintf(&input, "protocol=https\n")
	fmt.Fprintf(&input, "host=%s\n", remoteName)
	if operation == "store" && len(token) > 0 {
		fmt.Fprintf(&input, "password=%s\n", token[0])
	}
	cmd.Stdin = strings.NewReader(input.String())
	_, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("credential helper '%s' failed: %s", cmdName, string(exitErr.Stderr))
		}
		return fmt.Errorf("credential helper '%s' failed: %w", cmdName, err)
	}
	return nil
}

// runCredentialHelperGet runs a credential helper for the 'get' operation
func runCredentialHelperGet(helper, remoteName string) (string, error) {
	parts := strings.Fields(helper)
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid credential helper: %s", helper)
	}
	cmdName := "vec-credential-" + parts[0]
	args := append(parts[1:], "get")
	cmd := exec.Command(cmdName, args...)
	var input strings.Builder
	fmt.Fprintf(&input, "protocol=https\n")
	fmt.Fprintf(&input, "host=%s\n", remoteName)
	cmd.Stdin = strings.NewReader(input.String())
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("credential helper '%s' failed: %s", cmdName, string(exitErr.Stderr))
		}
		return "", fmt.Errorf("credential helper '%s' failed: %w", cmdName, err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "password=") {
			return strings.TrimPrefix(line, "password="), nil
		}
	}
	return "", nil
}

// parseVecCredential parses a Vec-compatible credential line
func parseVecCredential(line, remoteName string) string {
	// Expect format: https://username:password@host
	if !strings.HasPrefix(line, "https://") || !strings.Contains(line, remoteName) {
		return ""
	}
	parts := strings.SplitN(strings.TrimPrefix(line, "https://"), "@", 2)
	if len(parts) != 2 {
		return ""
	}
	credParts := strings.SplitN(parts[0], ":", 2)
	if len(credParts) != 2 {
		return ""
	}
	return credParts[1]
}
