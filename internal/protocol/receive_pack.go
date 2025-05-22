package protocol

import (
	"bufio"
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
		owner := r.PathValue("username")
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

		// Authorization check would normally go here
		// For now, we'll assume all users have write access
		// In a real implementation, you would check authorization based on the user context

		// Create buffered reader for request body
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		// Parse capabilities
		clientCaps, err := parseInitialCommand(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing capabilities: %v", err), http.StatusBadRequest)
			return
		}

		// Check if client supports side-band
		useSideBand := false
		for _, cap := range strings.Split(clientCaps, " ") {
			if cap == "side-band" || cap == "side-band-64k" {
				useSideBand = true
				break
			}
		}

		// Parse ref updates
		refUpdates, err := parseRefUpdates(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing ref updates: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("Received %d ref updates with capabilities: %s", len(refUpdates), clientCaps)
		for _, update := range refUpdates {
			log.Printf("  %s %s %s", update.OldHash, update.NewHash, update.RefName)
		}

		// Prepare temporary file for packfile
		packfilePath := filepath.Join(os.TempDir(), fmt.Sprintf("vec-packfile-%d", os.Getpid()))
		defer os.Remove(packfilePath)

		// Read packfile (if any) from the request into the temporary file
		packfileFile, err := os.Create(packfilePath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating temporary file: %v", err), http.StatusInternalServerError)
			return
		}
		defer packfileFile.Close()

		// Parse packfile if there is one
		hasPackfile, err := readPackfileTo(reader, packfileFile)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading packfile: %v", err), http.StatusBadRequest)
			return
		}

		// Process packfile if present
		if hasPackfile {
			// Rewind the file for reading
			if _, err := packfileFile.Seek(0, io.SeekStart); err != nil {
				http.Error(w, fmt.Sprintf("Error seeking packfile: %v", err), http.StatusInternalServerError)
				return
			}

			// Get packfile info for logging
			fileInfo, err := packfileFile.Stat()
			if err == nil {
				log.Printf("Received packfile of %d bytes", fileInfo.Size())
			}

			// Process the packfile
			if err := processPackfile(repoPath, packfilePath); err != nil {
				http.Error(w, fmt.Sprintf("Error processing packfile: %v", err), http.StatusInternalServerError)
				return
			}

			// Log progress if side-band is supported
			if useSideBand {
				progressWriter := &sideBandWriter{
					Writer:  w,
					Channel: SideBandProgress,
				}
				fmt.Fprintf(progressWriter, "Packfile received and processed successfully\n")
			}
		}

		// Validate and update refs
		results := updateRefs(repoPath, refUpdates)

		// Send response
		for _, result := range results {
			var responseMsg string
			if result.Success {
				responseMsg = fmt.Sprintf("ok %s\n", result.RefName)
			} else {
				responseMsg = fmt.Sprintf("ng %s %s\n", result.RefName, result.Error)
			}

			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, []byte(responseMsg)); err != nil {
					log.Printf("Error writing response: %v", err)
					break
				}
			} else {
				if err := WritePacketLine(w, []byte(responseMsg)); err != nil {
					log.Printf("Error writing response: %v", err)
					break
				}
			}
		}

		// End with a flush packet
		if err := WriteFlushPacket(w); err != nil {
			log.Printf("Error writing flush packet: %v", err)
		}
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

// sideBandWriter is a writer that wraps data with side-band encoding
type sideBandWriter struct {
	Writer  io.Writer
	Channel byte
}

// Write implements the io.Writer interface for sideBandWriter
func (w *sideBandWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	data := EncodeSideBand(w.Channel, p)
	if err := WritePacketLine(w.Writer, data); err != nil {
		return 0, err
	}

	return len(p), nil
}

// parseInitialCommand parses the initial command and extracts capabilities
func parseInitialCommand(reader io.Reader) (string, error) {
	data, isFlush, err := ReadPacketLine(reader)
	if err != nil {
		return "", err
	}
	if isFlush || len(data) == 0 {
		return "", fmt.Errorf("unexpected flush packet or empty data")
	}

	line := string(data)
	cmdLine, caps := ParseCapabilities(line)

	// Validate command format (should be "<old-hash> <new-hash> <ref-name>")
	parts := strings.Split(strings.TrimSpace(cmdLine), " ")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid command format: %s", cmdLine)
	}

	return caps, nil
}

// parseRefUpdates parses reference update commands from the request
func parseRefUpdates(reader io.Reader) ([]RefUpdate, error) {
	var updates []RefUpdate
	firstLine := true

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
		cmdLine := line

		// Handle capabilities in the first line
		if firstLine {
			cmdLine, _ = ParseCapabilities(line)
			firstLine = false
		}

		// Parse the command: "<old-hash> <new-hash> <ref-name>"
		parts := strings.Split(strings.TrimSpace(cmdLine), " ")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid ref update format: %s", cmdLine)
		}

		updates = append(updates, RefUpdate{
			OldHash: parts[0],
			NewHash: parts[1],
			RefName: parts[2],
		})
	}

	return updates, nil
}

// readPackfileTo reads a packfile from the request body and writes it to the specified writer
func readPackfileTo(reader io.Reader, writer io.Writer) (bool, error) {
	// Try to read the next 4 bytes to check if there's more data
	header := make([]byte, 4)
	n, err := io.ReadFull(reader, header)

	// No more data means no packfile
	if err == io.EOF || n < 4 {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	// Write the header to the output
	if _, err := writer.Write(header); err != nil {
		return false, err
	}

	// Check if it looks like a packfile (should start with "PACK")
	if string(header) != "PACK" {
		return false, fmt.Errorf("invalid packfile header: %s", string(header))
	}

	// Read the rest of the packfile
	if _, err := io.Copy(writer, reader); err != nil {
		return false, err
	}

	return true, nil
}

// processPackfile processes a packfile and stores its objects
func processPackfile(repoPath string, packfilePath string) error {
	// Get object storage path
	objectsPath := filepath.Join(repoPath, ".vec", "objects")

	// Ensure the objects directory exists
	if err := os.MkdirAll(objectsPath, 0755); err != nil {
		return fmt.Errorf("failed to create objects directory: %w", err)
	}

	// Parse and process the packfile
	objects, err := packfile.ParseModernPackfile(packfilePath, false)
	if err != nil {
		return fmt.Errorf("failed to parse packfile: %w", err)
	}

	// Store each object
	for _, obj := range objects {
		// Create object directory structure (first two characters of hash as directory name)
		objDir := filepath.Join(objectsPath, obj.Hash[:2])
		if err := os.MkdirAll(objDir, 0755); err != nil {
			return fmt.Errorf("failed to create object directory: %w", err)
		}

		// Object file path
		objPath := filepath.Join(objDir, obj.Hash[2:])

		// Skip if object already exists
		if _, err := os.Stat(objPath); err == nil {
			continue
		}

		// Use the Data field to access the object's content
		objData := obj.Data

		// Write object
		if err := os.WriteFile(objPath, objData, 0644); err != nil {
			return fmt.Errorf("failed to write object %s: %w", obj.Hash, err)
		}
	}

	return nil
}

// updateRefs updates repository references based on the received commands
func updateRefs(repoPath string, updates []RefUpdate) []RefUpdateResult {
	results := make([]RefUpdateResult, len(updates))

	// Verify that all requested old hashes match current state before making any changes
	for i, update := range updates {
		result := RefUpdateResult{
			RefName: update.RefName,
			Success: false,
		}

		// Get current ref value
		refPath := filepath.Join(repoPath, ".vec", update.RefName)
		currentHash, err := readRef(refPath)

		// Check if this is a force update (old hash is all zeros)
		isForce := update.OldHash == strings.Repeat("0", 64)

		// Validate old hash matches current hash (unless it's a force update)
		if !isForce && err == nil && currentHash != update.NewHash && currentHash != update.OldHash {
			result.Error = "reference has changed since last fetch"
			results[i] = result
			// Exit early with error status for all updates
			for j := i + 1; j < len(updates); j++ {
				results[j] = RefUpdateResult{
					RefName: updates[j].RefName,
					Success: false,
					Error:   "aborted due to earlier error",
				}
			}
			return results
		}

		// Mark this update as tentatively valid
		results[i] = RefUpdateResult{
			RefName: update.RefName,
			Success: true,
		}
	}

	// Now apply all updates
	for i, update := range updates {
		result := results[i]
		if !result.Success {
			// Skip updates that were already marked as failed
			continue
		}

		// Skip if old and new hashes are the same
		if update.OldHash == update.NewHash {
			continue
		}

		// Handle reference deletion
		if update.NewHash == strings.Repeat("0", 64) {
			// Delete the reference
			refPath := filepath.Join(repoPath, ".vec", update.RefName)
			if err := os.Remove(refPath); err != nil && !os.IsNotExist(err) {
				result.Success = false
				result.Error = fmt.Sprintf("failed to delete reference: %v", err)
			}
			results[i] = result
			continue
		}

		// Create or update reference
		refPath := filepath.Join(repoPath, ".vec", update.RefName)

		// Ensure directory exists
		refDir := filepath.Dir(refPath)
		if err := os.MkdirAll(refDir, 0755); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to create reference directory: %v", err)
			results[i] = result
			continue
		}

		// Write reference
		if err := os.WriteFile(refPath, []byte(update.NewHash), 0644); err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("failed to write reference: %v", err)
		}

		results[i] = result
	}

	return results
}

// readRef reads a reference file and returns its contents
func readRef(refPath string) (string, error) {
	data, err := os.ReadFile(refPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
