package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// ReceivePackHandler handles the receive-pack protocol endpoint (used for push)
func ReceivePackHandler(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get repository path from request context
		owner := r.PathValue("owner")
		repoName := r.PathValue("repo")

		// Check if repository exists
		if !repoManager.RepositoryExists(owner, repoName) {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Get repository path
		repoPath := repoManager.GetRepoPath(owner, repoName)

		// Set content type
		w.Header().Set("Content-Type", "application/x-vec-receive-pack-result")

		// Create buffered reader for request body
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		// Parse ref updates
		refUpdates, err := parseRefUpdates(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing ref updates: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("Received %d ref updates", len(refUpdates))
		for _, update := range refUpdates {
			log.Printf("  %s %s %s", update.OldHash, update.NewHash, update.RefName)
		}

		// Parse packfile if there is one
		packfileData, err := readPackfile(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading packfile: %v", err), http.StatusBadRequest)
			return
		}

		// Process packfile if present
		if len(packfileData) > 0 {
			log.Printf("Received packfile of %d bytes", len(packfileData))
			if err := processPackfile(repoPath, packfileData); err != nil {
				http.Error(w, fmt.Sprintf("Error processing packfile: %v", err), http.StatusInternalServerError)
				return
			}
		}

		// Update refs
		results := updateRefs(repoPath, refUpdates)

		// Send response
		for _, result := range results {
			if result.Success {
				WritePacketLine(w, []byte(fmt.Sprintf("ok %s\n", result.RefName)))
			} else {
				WritePacketLine(w, []byte(fmt.Sprintf("ng %s %s\n", result.RefName, result.Error)))
			}
		}

		// End with a flush packet
		WriteFlushPacket(w)
	}
}

// RefUpdate represents a reference update command
type RefUpdate struct {
	OldHash string
	NewHash string
	RefName string
}

// RefUpdateResult represents the result of a reference update
type RefUpdateResult struct {
	RefName string
	Success bool
	Error   string
}

// parseRefUpdates parses reference update commands from the request
func parseRefUpdates(reader io.Reader) ([]RefUpdate, error) {
	var updates []RefUpdate

	for {
		data, isFlush, err := ReadPacketLine(reader)
		if err != nil {
			return nil, err
		}

		// End of commands
		if isFlush {
			break
		}

		line := string(data)
		parts := strings.Split(strings.TrimSpace(line), " ")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid ref update format: %s", line)
		}

		updates = append(updates, RefUpdate{
			OldHash: parts[0],
			NewHash: parts[1],
			RefName: parts[2],
		})
	}

	return updates, nil
}

// readPackfile reads a packfile from the request body
func readPackfile(reader io.Reader) ([]byte, error) {
	// Check if there's more data after the ref updates
	peek := make([]byte, 4)
	n, err := reader.Read(peek)
	if err == io.EOF || n == 0 {
		// No packfile
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Read the rest of the packfile
	var packfile bytes.Buffer
	packfile.Write(peek[:n])
	if _, err := io.Copy(&packfile, reader); err != nil {
		return nil, err
	}

	return packfile.Bytes(), nil
}

// processPackfile processes a packfile and stores its objects
func processPackfile(repoPath string, packfileData []byte) error {
	// Create a temporary file for the packfile
	tempFile, err := os.CreateTemp("", "vec-packfile-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Write packfile data to the temporary file
	if _, err := tempFile.Write(packfileData); err != nil {
		return fmt.Errorf("failed to write packfile data: %w", err)
	}

	// Seek back to the beginning of the file
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to beginning of packfile: %w", err)
	}

	// Parse packfile
	parser := packfile.NewParser(tempFile)
	objects, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse packfile: %w", err)
	}

	// Store objects
	objectsPath := filepath.Join(repoPath, ".vec", "objects")
	storage := objects.NewStorage(objectsPath)
	for _, obj := range objects {
		if err := storage.StoreObject(obj); err != nil {
			return fmt.Errorf("failed to store object %s: %w", obj.Hash, err)
		}
	}

	return nil
}

// updateRefs updates repository references based on the received commands
func updateRefs(repoPath string, updates []RefUpdate) []RefUpdateResult {
	results := make([]RefUpdateResult, len(updates))

	for i, update := range updates {
		result := RefUpdateResult{
			RefName: update.RefName,
			Success: false,
		}

		// Skip if old and new hashes are the same
		if update.OldHash == update.NewHash {
			result.Success = true
			results[i] = result
			continue
		}

		// Handle reference deletion
		if update.NewHash == strings.Repeat("0", 64) {
			// Delete the reference
			refPath := filepath.Join(repoPath, ".vec", update.RefName)
			if err := os.Remove(refPath); err != nil {
				result.Error = fmt.Sprintf("failed to delete reference: %v", err)
			} else {
				result.Success = true
			}
			results[i] = result
			continue
		}

		// Create or update reference
		refPath := filepath.Join(repoPath, ".vec", update.RefName)

		// Ensure directory exists
		refDir := filepath.Dir(refPath)
		if err := os.MkdirAll(refDir, 0755); err != nil {
			result.Error = fmt.Sprintf("failed to create reference directory: %v", err)
			results[i] = result
			continue
		}

		// Write reference
		if err := os.WriteFile(refPath, []byte(update.NewHash), 0644); err != nil {
			result.Error = fmt.Sprintf("failed to write reference: %v", err)
		} else {
			result.Success = true
		}

		results[i] = result
	}

	return results
}
