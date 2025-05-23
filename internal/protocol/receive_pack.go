package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// ReceivePackHandler handles the receive-pack protocol endpoint
func ReceivePackHandler(repoManager *repository.Manager, logger *log.Logger, authorize func(*http.Request, *models.Repository) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("username")
		repoName := r.PathValue("repo")
		logger.Printf("RECEIVE_PACK: Request for owner=%s, repo=%s", owner, repoName)

		exists, err := repoManager.RepositoryExists(owner, repoName)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error checking repository: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !exists {
			logger.Printf("RECEIVE_PACK: Repository not found: owner=%s, repo=%s", owner, repoName)
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		repoPath, err := repoManager.GetRepoPath(owner, repoName)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Invalid repo path: %v", err)
			http.Error(w, "Invalid repository path", http.StatusBadRequest)
			return
		}

		// Try to get the repository from context first
		var repo *models.Repository
		repoCtx, ok := r.Context().Value(middleware.RepositoryContextKey).(*middleware.RepositoryContext)
		if ok && repoCtx.Repository != nil {
			repo = repoCtx.Repository
			// Ensure Path is set
			if repo.Path == "" {
				repo.Path = repoPath
			}
		} else {
			// Fallback to minimal repository object
			repo = &models.Repository{
				Path: repoPath,
				Name: repoName,
			}
		}

		if err := authorize(r, repo); err != nil {
			logger.Printf("RECEIVE_PACK: Authorization failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-vec")
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		clientCaps, err := parseInitialCommand(reader)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error parsing capabilities: %v", err)
			http.Error(w, fmt.Sprintf("Error parsing capabilities: %v", err), http.StatusBadRequest)
			return
		}

		useSideBand := strings.Contains(clientCaps, "side-band") || strings.Contains(clientCaps, "side-band-64k")
		logger.Printf("RECEIVE_PACK: Client capabilities: %s, side-band: %v", clientCaps, useSideBand)

		refUpdates, err := parseRefUpdates(reader)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error parsing ref updates: %v", err)
			http.Error(w, fmt.Sprintf("Error parsing ref updates: %v", err), http.StatusBadRequest)
			return
		}
		logger.Printf("RECEIVE_PACK: Received %d ref updates", len(refUpdates))

		packfilePath := filepath.Join(os.TempDir(), fmt.Sprintf("vec-packfile-%d", os.Getpid()))
		defer os.Remove(packfilePath)

		packfileFile, err := os.Create(packfilePath)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error creating temp file: %v", err)
			http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
			return
		}
		defer packfileFile.Close()

		hasPackfile, err := readPackfileTo(reader, packfileFile)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error reading packfile: %v", err)
			http.Error(w, fmt.Sprintf("Error reading packfile: %v", err), http.StatusBadRequest)
			return
		}

		if hasPackfile {
			if _, err := packfileFile.Seek(0, io.SeekStart); err != nil {
				logger.Printf("RECEIVE_PACK: Error seeking packfile: %v", err)
				http.Error(w, "Error processing packfile", http.StatusInternalServerError)
				return
			}
			fileInfo, _ := packfileFile.Stat()
			logger.Printf("RECEIVE_PACK: Received packfile of %d bytes", fileInfo.Size())

			if err := processPackfile(repoPath, packfilePath); err != nil {
				logger.Printf("RECEIVE_PACK: Error processing packfile: %v", err)
				if useSideBand {
					WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error processing packfile: %v\n", err)))
				}
				http.Error(w, "Error processing packfile", http.StatusInternalServerError)
				return
			}

			if useSideBand {
				if err := WriteSideBand(w, SideBandProgress, []byte("Packfile processed successfully\n")); err != nil {
					logger.Printf("RECEIVE_PACK: Error sending progress: %v", err)
				}
			}
		}

		results, err := updateRefs(repoManager, repo, refUpdates, useSideBand, w)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error updating refs: %v", err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error updating refs: %v\n", err)))
			}
			http.Error(w, "Error updating refs", http.StatusInternalServerError)
			return
		}

		// Sync repository data with the database after successful updates
		if syncManager := repoManager.GetSyncManager(); syncManager != nil {
			if useSideBand {
				WriteSideBand(w, SideBandProgress, []byte("Syncing repository metadata...\n"))
			}

			if err := syncManager.SyncRepository(repo); err != nil {
				logger.Printf("RECEIVE_PACK: Error syncing repository data: %v", err)
				if useSideBand {
					WriteSideBand(w, SideBandProgress, []byte(fmt.Sprintf("Warning: Error syncing repository metadata: %v\n", err)))
				}
				// We don't fail the request if sync fails, just log it
			} else if useSideBand {
				WriteSideBand(w, SideBandProgress, []byte("Repository metadata synced successfully\n"))
			}
		}

		for _, result := range results {
			responseMsg := fmt.Sprintf("ok %s\n", result.RefName)
			if !result.Success {
				responseMsg = fmt.Sprintf("ng %s %s\n", result.RefName, result.Error)
			}
			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, []byte(responseMsg)); err != nil {
					logger.Printf("RECEIVE_PACK: Error writing response: %v", err)
					break
				}
			} else {
				if err := WritePacketLine(w, []byte(responseMsg)); err != nil {
					logger.Printf("RECEIVE_PACK: Error writing response: %v", err)
					break
				}
			}
		}

		if err := WriteFlushPacket(w); err != nil {
			logger.Printf("RECEIVE_PACK: Error writing flush packet: %v", err)
		}
		logger.Printf("RECEIVE_PACK: Completed request for %s/%s", owner, repoName)
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

// parseInitialCommand parses the initial command and extracts capabilities
func parseInitialCommand(reader io.Reader) (string, error) {
	data, isFlush, err := ReadPacketLine(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read initial command: %w", err)
	}
	if isFlush || len(data) == 0 {
		return "", fmt.Errorf("unexpected flush packet or empty data")
	}

	line := string(data)
	cmdLine, caps := ParseCapabilities(line)
	parts := strings.Fields(cmdLine)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid command format: %s", cmdLine)
	}
	if !isValidCommitHash(parts[0]) || !isValidCommitHash(parts[1]) {
		return "", fmt.Errorf("invalid hash in command: %s", cmdLine)
	}
	return caps, nil
}

// parseRefUpdates parses reference update commands
func parseRefUpdates(reader io.Reader) ([]RefUpdate, error) {
	var updates []RefUpdate
	firstLine := true

	for {
		data, isFlush, err := ReadPacketLine(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read ref update: %w", err)
		}
		if isFlush {
			break
		}

		line := string(data)
		cmdLine := line
		if firstLine {
			cmdLine, _ = ParseCapabilities(line)
			firstLine = false
		}

		parts := strings.Fields(cmdLine)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid ref update format: %s", cmdLine)
		}
		if !isValidCommitHash(parts[0]) || !isValidCommitHash(parts[1]) {
			return nil, fmt.Errorf("invalid hash in ref update: %s", cmdLine)
		}
		if !strings.HasPrefix(parts[2], "refs/") {
			return nil, fmt.Errorf("invalid ref name: %s", parts[2])
		}

		updates = append(updates, RefUpdate{
			OldHash: parts[0],
			NewHash: parts[1],
			RefName: parts[2],
		})
	}

	return updates, nil
}

// readPackfileTo reads a packfile from the request body
func readPackfileTo(reader io.Reader, writer io.Writer) (bool, error) {
	header := make([]byte, 4)
	n, err := io.ReadFull(reader, header)
	if err == io.EOF || n < 4 {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read packfile header: %w", err)
	}

	if _, err := writer.Write(header); err != nil {
		return false, fmt.Errorf("failed to write packfile header: %w", err)
	}
	if string(header) != "PACK" {
		return false, fmt.Errorf("invalid packfile header: %s", string(header))
	}

	if _, err := io.Copy(writer, reader); err != nil {
		return false, fmt.Errorf("failed to read packfile data: %w", err)
	}
	return true, nil
}

// processPackfile processes a packfile and stores its objects
func processPackfile(repoPath, packfilePath string) error {
	objectsPath := filepath.Join(repoPath, ".vec", "objects")
	if err := os.MkdirAll(objectsPath, 0755); err != nil {
		return fmt.Errorf("failed to create objects directory: %s: %w", objectsPath, err)
	}

	objects, err := packfile.ParseModernPackfile(packfilePath, true)
	if err != nil {
		return fmt.Errorf("failed to parse packfile %s: %w", packfilePath, err)
	}

	for _, obj := range objects {
		if !isValidCommitHash(obj.Hash) {
			return fmt.Errorf("invalid object hash: %s", obj.Hash)
		}
		objDir := filepath.Join(objectsPath, obj.Hash[:2])
		if err := os.MkdirAll(objDir, 0755); err != nil {
			return fmt.Errorf("failed to create object directory %s: %w", objDir, err)
		}

		objPath := filepath.Join(objDir, obj.Hash[2:])
		if _, err := os.Stat(objPath); err == nil {
			continue
		}

		if err := os.WriteFile(objPath, obj.Data, 0644); err != nil {
			return fmt.Errorf("failed to write object %s: %w", objPath, err)
		}
	}
	return nil
}

// updateRefs updates repository references using RefManager
func updateRefs(repoManager *repository.Manager, repo *models.Repository, updates []RefUpdate, useSideBand bool, w http.ResponseWriter) ([]RefUpdateResult, error) {
	results := make([]RefUpdateResult, len(updates))

	for i, update := range updates {
		results[i] = RefUpdateResult{RefName: update.RefName, Success: true}
		currentHash, err := readRef(repoManager, repo, update.RefName)
		isForce := update.OldHash == strings.Repeat("0", len(update.OldHash))
		if !isForce && err == nil && currentHash != update.OldHash {
			results[i].Success = false
			results[i].Error = "reference has changed since last fetch"
			for j := i + 1; j < len(updates); j++ {
				results[j] = RefUpdateResult{
					RefName: updates[j].RefName,
					Success: false,
					Error:   "aborted due to earlier error",
				}
			}
			return results, nil
		}
	}

	err := repoManager.RunTransaction(repo, func(tx *repository.RefTransaction) error {
		for i, update := range updates {
			if !results[i].Success {
				continue
			}
			if update.OldHash == update.NewHash {
				continue
			}
			if update.NewHash == strings.Repeat("0", len(update.NewHash)) {
				tx.Delete(update.RefName)
			} else {
				tx.Update(update.RefName, update.NewHash, false)
			}
		}
		return nil
	})

	if err != nil {
		for i := range results {
			if results[i].Success {
				results[i].Success = false
				results[i].Error = fmt.Sprintf("transaction failed: %v", err)
			}
		}
		return results, err
	}

	return results, nil
}

// readRef reads a reference using RefManager
func readRef(repoManager *repository.Manager, repo *models.Repository, refName string) (string, error) {
	ref, err := repoManager.GetRef(repo, refName)
	if err != nil {
		if errors.Is(err, repository.ErrReferenceNotFound) {
			return "", nil
		}
		return "", err
	}
	return ref.Value, nil
}

// isValidCommitHash checks if a string is a valid SHA-1 or SHA-256 hash
func isValidCommitHash(hash string) bool {
	if len(hash) != 40 && len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
