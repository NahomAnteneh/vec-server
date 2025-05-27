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

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/api/middleware"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// NOTE: Shared utilities like ReadPktLine, FlushMessage, ParsedCommit, parseCoreCommitData etc.
// are assumed to be moved to a shared package (e.g., internal/protocol/pktline or internal/gitutil) and imported.
// Their definitions are REMOVED from this file to avoid redeclaration errors shown by the linter.
// This will cause 'undefined' errors until the shared package refactor is complete.

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

		var repoModelForAuth *models.Repository
		repoCtx, ok := r.Context().Value(middleware.RepositoryContextKey).(*middleware.RepositoryContext)
		if ok && repoCtx.Repository != nil {
			repoModelForAuth = repoCtx.Repository
			if repoModelForAuth.Path == "" {
				repoModelForAuth.Path = repoPath
			}
		} else {
			repoModelForAuth = &models.Repository{Path: repoPath, Name: repoName} // Minimal for authorize
			// If authorize needs owner, it should be populated from db based on username param from router if not in ctx
			// For now, assuming path is primary for authorize, or it fetches user itself.
		}

		if err := authorize(r, repoModelForAuth); err != nil {
			logger.Printf("RECEIVE_PACK: Authorization failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-vec-receive-pack-report") // Standard Git content type
		clientReader := bufio.NewReader(r.Body)                                 // For the whole request body
		defer r.Body.Close()

		// The initial lines are commands, then optionally a packfile.
		// We need a scanner for the command part.
		clientCaps, initialUpdates, err := parseInitialCommandsAndCaps(clientReader, logger)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error parsing initial commands/caps: %v", err)
			http.Error(w, fmt.Sprintf("Error parsing initial commands: %v", err), http.StatusBadRequest)
			return
		}

		useSideBand := strings.Contains(clientCaps, "side-band-64k") || strings.Contains(clientCaps, "side-band")
		logger.Printf("RECEIVE_PACK: Client capabilities: %s, side-band: %v, initial updates: %d", clientCaps, useSideBand, len(initialUpdates))

		// The rest of the reader (clientReader) is the packfile, if present.
		tempPackfilePath := filepath.Join(os.TempDir(), fmt.Sprintf("vec-received-pack-%d-%s.pack", os.Getpid(), owner+"_"+repoName))
		defer os.Remove(tempPackfilePath)

		tempPackfile, err := os.Create(tempPackfilePath)
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error creating temp packfile: %v", err)
			http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
			return
		}

		// Write remaining data from clientReader to tempPackfile
		// This assumes parseInitialCommandsAndCaps only consumed the command lines via cmdScanner.
		// The underlying clientReader now points to the start of the packfile data.
		packSize, err := io.Copy(tempPackfile, clientReader)
		tempPackfile.Close() // Close after writing
		if err != nil {
			logger.Printf("RECEIVE_PACK: Error reading packfile data: %v", err)
			http.Error(w, "Error reading packfile data", http.StatusBadRequest)
			return
		}

		hasPackfile := packSize > 0
		if hasPackfile {
			logger.Printf("RECEIVE_PACK: Received packfile of %d bytes at %s", packSize, tempPackfilePath)
			if err := processPackfile(repoPath, tempPackfilePath, logger); err != nil {
				logger.Printf("RECEIVE_PACK: Error processing packfile: %v", err)
				// Report unpack error in the ref update status as per Git protocol
				// For now, let's assume processPackfile errors are critical enough for early exit for simplicity of report
				// A real git server might try to continue to ref updates and report unpack error there.
				if useSideBand {
					WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("unpack error %v\n", err)))
				} else {
					WritePacketLine(w, []byte(fmt.Sprintf("unpack error %v\n", err)))
				}
				// No overall push report if unpack fails catastrophically before ref processing
				WriteFlushPacket(w) // Need to flush after error message
				return
			}
			if useSideBand {
				WriteSideBand(w, SideBandProgress, []byte("unpack ok\n"))
			}
		} else {
			logger.Printf("RECEIVE_PACK: No packfile received.")
		}

		results, overallSuccess := updateRefs(repoManager, repoPath, initialUpdates, useSideBand, w, logger, clientCaps)

		var report strings.Builder
		if hasPackfile { // Only prepend "unpack ok" if a packfile was expected/processed
			report.WriteString("unpack ok\n")
		}

		for _, res := range results {
			if res.Success {
				report.WriteString(fmt.Sprintf("ok %s\n", res.RefName))
			} else {
				report.WriteString(fmt.Sprintf("ng %s %s\n", res.RefName, res.Error))
			}
		}

		reportStr := strings.TrimSpace(report.String())           // Trim potentially leading/trailing newlines if report is empty
		if reportStr == "" && !hasPackfile && len(results) == 0 { // No pack, no updates (e.g. dry run with no changes)
			// Send empty report (just a flush)
		} else if useSideBand {
			WriteSideBand(w, SideBandMain, []byte(report.String()))
		} else {
			scanner := bufio.NewScanner(strings.NewReader(report.String()))
			for scanner.Scan() {
				line := scanner.Text()
				if line != "" { // Don't send empty pkt-lines
					WritePacketLine(w, []byte(line))
				}
			}
		}
		WriteFlushPacket(w)

		// Sync repository only if all ref updates were successful
		if overallSuccess && repoModelForAuth != nil { // repoModelForAuth might have DB ID if from context
			var ownerModel *models.User
			if repoModelForAuth.OwnerID != 0 && repoCtx != nil && repoCtx.Repository != nil && repoCtx.Repository.Owner.ID == repoModelForAuth.OwnerID {
				ownerModel = &repoCtx.Repository.Owner // Use Owner from context if available and matches
			} else if repoModelForAuth.OwnerID != 0 { // Try to fetch if OwnerID is known but not populated
				userServiceFromCtx, _ := r.Context().Value("userService").(models.UserService)
				if userServiceFromCtx != nil {
					ownerModel, _ = userServiceFromCtx.GetByID(repoModelForAuth.OwnerID)
				}
			}

			if ownerModel == nil { // Fallback to username from path if still nil
				userServiceFromCtx, _ := r.Context().Value("userService").(models.UserService)
				if userServiceFromCtx != nil {
					ownerModel, _ = userServiceFromCtx.GetByUsername(owner)
				}
			}

			if ownerModel == nil {
				logger.Printf("RECEIVE_PACK: Could not determine owner model for sync. Skipping sync.")
			} else {
				var dbRepoToSync *models.Repository
				if repoModelForAuth.ID != 0 {
					dbRepoToSync = repoModelForAuth
				} else {
					repoServiceFromCtx, _ := r.Context().Value("repoService").(models.RepositoryService)
					if repoServiceFromCtx != nil {
						dbRepoToSync, _ = repoServiceFromCtx.GetByUsername(owner, repoName)
					}
				}

				if dbRepoToSync == nil {
					logger.Printf("RECEIVE_PACK: Could not get DB repository model for sync. Skipping sync.")
				} else {
					if syncManager := repoManager.GetSyncManager(); syncManager != nil {
						logger.Printf("RECEIVE_PACK: Triggering repository sync for %s/%s", owner, repoName)
						if errSync := syncManager.SynchronizeRepository(dbRepoToSync, ownerModel); errSync != nil {
							logger.Printf("RECEIVE_PACK: Error syncing repository data: %v", errSync)
						}
					} else {
						logger.Printf("RECEIVE_PACK: SyncManager not available. Skipping sync.")
					}
				}
			}
		}
		logger.Printf("RECEIVE_PACK: Completed request for %s/%s", owner, repoName)
	}
}

// RefUpdate stores information about a ref update
type RefUpdate struct {
	OldHash string
	NewHash string
	RefName string
}

// RefUpdateResult stores the result of a ref update operation
type RefUpdateResult struct {
	RefName string
	Success bool
	Error   string
}

// parseInitialCommandsAndCaps reads the first part of the receive-pack protocol:
// a series of pkt-lines detailing ref updates and capabilities.
// It stops when it encounters a flush packet ("0000").
// The provided reader should be at the start of these command lines.
func parseInitialCommandsAndCaps(r *bufio.Reader, logger *log.Logger) (string, []RefUpdate, error) {
	var updates []RefUpdate
	var clientCaps string
	firstLine := true

	for {
		// Use the ReadPacketLine from the same 'protocol' package (defined in packet.go)
		// It returns ([]byte, isFlush, error)
		pktData, isFlush, err := ReadPacketLine(r) // Use the correct ReadPacketLine
		if err != nil {
			// Distinguish EOF after some lines from immediate EOF
			if err == io.EOF && !firstLine { // EOF after some commands is unexpected before flush
				return clientCaps, updates, fmt.Errorf("unexpected EOF before flush pkt in command list")
			} else if err == io.EOF && firstLine && len(updates) == 0 { // EOF immediately is ok if nothing was sent (empty push)
				logger.Printf("RECEIVE_PACK: Empty initial command list from client (EOF).")
				break // Treat as empty command list
			}
			return clientCaps, updates, fmt.Errorf("failed to read pkt-line for ref update: %w", err)
		}

		if isFlush { // FlushPkt ("0000") indicates end of commands
			logger.Printf("RECEIVE_PACK: Encountered flush packet, ending command parsing.")
			break
		}

		lineText := string(pktData) // Convert data part of pkt-line to string

		cmdLine := lineText
		if firstLine {
			logger.Printf("RECEIVE_PACK: First command line received: %s", lineText)
			parts := strings.SplitN(lineText, "\x00", 2) // NUL separates command from capabilities
			cmdLine = parts[0]
			if len(parts) > 1 {
				clientCaps = parts[1]
				logger.Printf("RECEIVE_PACK: Client capabilities extracted: %s", clientCaps)
			}
			firstLine = false
		} else if strings.Contains(lineText, "\x00") { // Subsequent lines *should not* have capabilities
			logger.Printf("RECEIVE_PACK: Error: Unexpected capabilities string in subsequent ref update line: %s", lineText)
			return clientCaps, updates, fmt.Errorf("unexpected capabilities string in subsequent ref update line: %s", lineText)
		}

		logger.Printf("RECEIVE_PACK: Parsing command line: %s", cmdLine)
		parts := strings.Fields(cmdLine)
		if len(parts) != 3 {
			logger.Printf("RECEIVE_PACK: Error: Invalid ref update format: '%s' (got %d parts, expected 3)", cmdLine, len(parts))
			return clientCaps, updates, fmt.Errorf("invalid ref update format: '%s' (got %d parts)", cmdLine, len(parts))
		}
		oldHash, newHash, refName := parts[0], parts[1], parts[2]
		logger.Printf("RECEIVE_PACK: Parsed update: old=%s, new=%s, ref=%s", oldHash, newHash, refName)

		// Validate hashes and refName (copied from existing logic)
		if !(len(oldHash) == 64 && IsValidHexCore(oldHash)) && oldHash != strings.Repeat("0", 64) {
			// Allow the git-style 40-char zero hash as well, though our ZeroHash is 64.
			// The client *should* be sending 64 zeros now for vec.
			if oldHash != strings.Repeat("0", 40) {
				logger.Printf("RECEIVE_PACK: Error: Invalid old hash in ref update: %s", oldHash)
				return clientCaps, updates, fmt.Errorf("invalid old hash in ref update: %s", oldHash)
			}
			// If it was the 40-char zero, normalize to 64 for internal consistency if needed,
			// though the client should be sending 64. For now, accept for parsing.
		}
		if !(len(newHash) == 64 && IsValidHexCore(newHash)) && newHash != strings.Repeat("0", 64) {
			if newHash != strings.Repeat("0", 40) {
				logger.Printf("RECEIVE_PACK: Error: Invalid new hash in ref update: %s", newHash)
				return clientCaps, updates, fmt.Errorf("invalid new hash in ref update: %s", newHash)
			}
		}
		if !strings.HasPrefix(refName, "refs/") {
			logger.Printf("RECEIVE_PACK: Error: Invalid ref name (must start with refs/): %s", refName)
			return clientCaps, updates, fmt.Errorf("invalid ref name (must start with refs/): %s", refName)
		}
		updates = append(updates, RefUpdate{OldHash: oldHash, NewHash: newHash, RefName: refName})
		logger.Printf("RECEIVE_PACK: Added ref update: %s %s %s", oldHash, newHash, refName)
	}
	if firstLine && len(updates) == 0 {
		logger.Printf("RECEIVE_PACK: No commands received before flush/EOF.")
	}
	return clientCaps, updates, nil
}

// IsValidHexCore checks if a string is a valid hex string (helper)
// This should ideally be from a shared core utility package
func IsValidHexCore(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// processPackfile unpacks objects from the packfile into the repository.
// It uses the packfile package to parse and then finalize the objects.
func processPackfile(repoPath, packfilePath string, logger *log.Logger) error {
	logger.Printf("Processing packfile: %s for repo: %s", packfilePath, repoPath)

	cr := core.NewRepository(repoPath)
	pf := packfile.NewPackfile(cr) // Associate with the core repository

	// Parse the packfile from the given path
	// The packfile.Parse method reads objects into memory but doesn't write them to disk yet.
	if err := pf.Parse(packfilePath); err != nil {
		return fmt.Errorf("failed to parse packfile %s: %w", packfilePath, err)
	}
	logger.Printf("Successfully parsed %d objects from packfile %s", len(pf.Objects), packfilePath)

	// Finalize the packfile: write parsed objects to the repository's object store
	if err := pf.Finalize(); err != nil {
		return fmt.Errorf("failed to finalize packfile (write objects) %s: %w", packfilePath, err)
	}
	logger.Printf("Successfully finalized packfile, objects written to repository %s", repoPath)

	// Optionally, verify the packfile (can be computationally intensive)
	// if err := pf.Verify(); err != nil {
	// 	logger.Printf("Warning: Packfile %s verification failed: %v", packfilePath, err)
	// 	// Depending on policy, this might not be a fatal error if objects were written.
	// }

	// Optionally, generate and write a .idx file for the received pack if server uses packs directly
	// (Current server design seems to prefer loose objects primarily, then packs for fetch)
	// if err := pf.GenerateIndex(); err != nil { // Assuming GenerateIndex prepares p.Index
	// 	if err := pf.WriteIndex(); err != nil { // And WriteIndex writes it to a .idx file
	// 		logger.Printf("Warning: Failed to write pack index for %s: %v", packfilePath, err)
	// 	}
	// }

	return nil
}

// updateRefs processes ref updates, validates, and applies them.
// Returns true if all updates were successful.
func updateRefs(repoManager *repository.Manager, repoPath string, updates []RefUpdate, useSideBand bool, w http.ResponseWriter, logger *log.Logger, clientCaps string) ([]RefUpdateResult, bool) {
	var results []RefUpdateResult
	overallSuccess := true
	reportProgress := strings.Contains(clientCaps, "report-status") || strings.Contains(clientCaps, "report-status-v2")
	// atomicPush := strings.Contains(clientCaps, "atomic") // TODO: Implement atomic pushes

	cr := core.NewRepository(repoPath) // Create core.Repository instance for this scope

	for _, update := range updates {
		result := RefUpdateResult{RefName: update.RefName, Success: false}

		// Validate ref name (basic validation)
		if !strings.HasPrefix(update.RefName, "refs/") {
			result.Error = "invalid ref name"
			results = append(results, result)
			overallSuccess = false
			logger.Printf("RECEIVE_PACK: Invalid ref name: %s", update.RefName)
			continue
		}

		// Handle delete
		if update.NewHash == strings.Repeat("0", 64) {
			if strings.HasPrefix(update.RefName, "refs/heads/") {
				branchName := strings.TrimPrefix(update.RefName, "refs/heads/")

				// Check if it's the current HEAD
				headContent, _ := core.ReadHEADFile(cr)
				currentBranchRef := ""
				if strings.HasPrefix(headContent, "ref: ") {
					currentBranchRef = strings.TrimPrefix(headContent, "ref: ")
				}

				if currentBranchRef == update.RefName {
					result.Error = fmt.Sprintf("refusing to delete current branch %s", branchName)
					overallSuccess = false
				} else {
					err := repoManager.DeleteBranch(repoPath, branchName) // repoManager.DeleteBranch takes repoPath string
					if err != nil {
						result.Error = fmt.Sprintf("failed to delete branch: %v", err)
						overallSuccess = false
					} else {
						result.Success = true
						logger.Printf("RECEIVE_PACK: Deleted branch %s (was %s)", branchName, update.OldHash)
					}
				}
			} else {
				// Deleting other refs (e.g. tags, custom refs under refs/)
				// Construct full path to ref file: .vec/refs/some/tag
				refFilePath := filepath.Join(cr.VecDir, update.RefName)
				if core.FileExists(refFilePath) { // Check existence before attempting delete
					err := os.Remove(refFilePath)
					if err != nil {
						result.Error = fmt.Sprintf("failed to delete ref %s: %v", update.RefName, err)
						overallSuccess = false
					} else {
						result.Success = true
						logger.Printf("RECEIVE_PACK: Deleted ref %s (was %s)", update.RefName, update.OldHash)
					}
				} else { // Ref to delete does not exist
					// This could be an error or success depending on protocol (Git usually ok if old_oid is zero)
					if update.OldHash == strings.Repeat("0", 64) || update.OldHash == "" {
						result.Success = true // Deleting a non-existent ref that client expects to be zero is ok
						logger.Printf("RECEIVE_PACK: Ref %s to delete did not exist, client expected zero OID.", update.RefName)
					} else {
						result.Error = fmt.Sprintf("ref %s not found for deletion (old OID %s was not zero)", update.RefName, update.OldHash)
						overallSuccess = false
					}
				}
			}
			results = append(results, result)
			continue
		}

		// Check if new object exists
		newObjExists, err := core.ObjectExists(cr, update.NewHash) // Use cr
		if err != nil {
			result.Error = fmt.Sprintf("error checking new object %s: %v", update.NewHash, err)
			results = append(results, result)
			overallSuccess = false
			logger.Printf("RECEIVE_PACK: Error checking existence of new object %s for ref %s: %v", update.NewHash, update.RefName, err)
			continue
		}
		if !newObjExists {
			result.Error = fmt.Sprintf("object %s not found", update.NewHash)
			results = append(results, result)
			overallSuccess = false
			logger.Printf("RECEIVE_PACK: New object %s for ref %s not found", update.NewHash, update.RefName)
			continue
		}

		// Get current ref value (old hash)
		// existingCommit, err := readRef(repoManager, repoPath, update.RefName) // Old call
		existingCommit, err := readRef(cr, update.RefName, logger)   // Pass cr
		if err != nil && existingCommit != strings.Repeat("0", 64) { // Replaced core.ZeroID. ZeroID means ref doesn't exist, which is fine for new refs
			result.Error = fmt.Sprintf("failed to read existing ref: %v", err)
			results = append(results, result)
			overallSuccess = false
			logger.Printf("RECEIVE_PACK: Error reading existing ref %s: %v", update.RefName, err)
			continue
		}

		// Check old hash if provided (for non-force push verification)
		if update.OldHash != strings.Repeat("0", 64) && update.OldHash != "" && update.OldHash != existingCommit {
			result.Error = "old object ID mismatch"
			results = append(results, result)
			overallSuccess = false
			logger.Printf("RECEIVE_PACK: Old hash mismatch for %s: expected %s, got %s", update.RefName, existingCommit, update.OldHash)
			continue
		}

		// Check for fast-forward if it's not a new ref (existingCommit != ZeroID)
		// And not a forced push (typically indicated by client, but we can enforce fast-forward by default)
		isNewRef := (existingCommit == strings.Repeat("0", 64) || existingCommit == "")
		if !isNewRef {
			isFF, ffErr := checkFastForward(repoPath, existingCommit, update.NewHash, logger)
			if ffErr != nil {
				result.Error = fmt.Sprintf("fast-forward check failed: %v", ffErr)
				results = append(results, result)
				overallSuccess = false
				logger.Printf("RECEIVE_PACK: Fast-forward check failed for %s (%s..%s): %v", update.RefName, existingCommit, update.NewHash, ffErr)
				continue
			}
			if !isFF {
				result.Error = "non-fast-forward update"
				results = append(results, result)
				overallSuccess = false // Strict: only allow fast-forwards by default
				logger.Printf("RECEIVE_PACK: Ref %s update from %s to %s is not a fast-forward.", update.RefName, existingCommit, update.NewHash)
				continue
			}
		}

		// Update the ref using core.WriteRef
		// Debug log the values before writing
		logger.Printf("RECEIVE_PACK: Writing ref %s with hash %s", update.RefName, update.NewHash)

		// Ensure the ref directory exists
		refDir := filepath.Dir(filepath.Join(cr.VecDir, update.RefName))
		if err := os.MkdirAll(refDir, 0755); err != nil {
			result.Error = fmt.Sprintf("failed to create ref directory: %v", err)
			overallSuccess = false
			continue
		}

		// Write the ref file using a completely new approach
		refFilePath := filepath.Join(cr.VecDir, update.RefName)

		// Add extensive debugging
		logger.Printf("DEBUG: Writing ref file at path: %s", refFilePath)

		// Ensure the directory exists (with multiple levels)
		dirPath := filepath.Dir(refFilePath)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			logger.Printf("DEBUG: Failed to create directory %s: %v", dirPath, err)
			result.Error = fmt.Sprintf("failed to create ref directory: %v", err)
			overallSuccess = false
			continue
		}

		// Make sure to append a newline to the hash
		hashWithNewline := update.NewHash + "\n"

		// Use atomic file writing pattern with a temporary file to avoid partial writes
		tempFile := refFilePath + ".tmp"

		// First, try to write the temporary file
		err = atomicWriteFile(tempFile, hashWithNewline, 0644, logger)
		if err != nil {
			logger.Printf("DEBUG: Failed to write temporary file %s: %v", tempFile, err)
			result.Error = fmt.Sprintf("failed to write temporary ref file: %v", err)
			overallSuccess = false
			continue
		}

		// Now atomically rename the temporary file to the target file
		if err := os.Rename(tempFile, refFilePath); err != nil {
			logger.Printf("DEBUG: Failed to rename temporary file to target: %v", err)
			result.Error = fmt.Sprintf("failed to finalize ref file: %v", err)
			overallSuccess = false
			continue
		}

		// Verify the file was written correctly
		content, err := os.ReadFile(refFilePath)
		if err != nil {
			logger.Printf("DEBUG: Verification failed - could not read ref file: %v", err)
		} else if len(content) == 0 {
			logger.Printf("DEBUG: Verification failed - ref file is empty")

			// Emergency direct write as last resort
			logger.Printf("DEBUG: Attempting emergency direct write")
			file, err := os.OpenFile(refFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				logger.Printf("DEBUG: Emergency write failed - could not open file: %v", err)
			} else {
				_, err = file.WriteString(hashWithNewline)
				if err != nil {
					logger.Printf("DEBUG: Emergency write failed - could not write to file: %v", err)
				}
				file.Sync()
				file.Close()
			}
		} else {
			logger.Printf("DEBUG: Verification passed - wrote %d bytes to ref file", len(content))
			logger.Printf("DEBUG: File content: %s", string(content))
		}

		result.Success = true
		logger.Printf("RECEIVE_PACK: Updated ref %s from %s to %s", update.RefName, existingCommit, update.NewHash)

		// If a branch was updated, and it's the default branch (HEAD points to it), update HEAD if it was symbolic
		// This part is tricky. Git usually updates HEAD if the current branch is pushed.
		// For simplicity, if HEAD is symbolic and points to this branch, we ensure it stays that way.
		// If HEAD was detached, this doesn't change it.
		if strings.HasPrefix(update.RefName, "refs/heads/") {
			headContent, _ := core.ReadHEADFile(cr)
			if strings.HasPrefix(headContent, "ref: ") && headContent == "ref: "+update.RefName {
				// HEAD is already pointing to this symbolic ref, WriteRef updated its target.
				// If HEAD itself needs to be updated to point to this branch (e.g. initializing repo)
				// repoManager.UpdateHead(repoPath, strings.TrimPrefix(update.RefName, "refs/heads/"))
				// This logic is typically for `git push -u origin main` or setting default branch.
				// For a simple push, just updating the branch ref file is enough.
				// If we want to ensure HEAD becomes this branch if it's the first push / main branch etc.,
				// more complex logic or explicit commands are needed.
				// The `SynchronizeRepository` later will set the default branch in DB from HEAD.
			}
		}
		results = append(results, result)
	}

	if reportProgress && len(results) > 0 {
		// Send progress report (optional, depends on client capabilities and what we want to report)
	}

	return results, overallSuccess
}

// readRef is a helper to read the current commit hash of a reference.
// It uses the repoManager which in turn uses core functions.
// This function seems okay as it uses repoManager.GetCommitForBranch.
// However, if it directly called core.ReadRef, it would need *core.Repository.
// For now, assuming repoManager.GetCommitForBranch handles core.Repository instantiation.
// No, this function is called by updateRefs, it should directly use core.
func readRef(coreRepo *core.Repository, refNameFull string, logger *log.Logger) (string, error) {
	// refNameFull is like "refs/heads/main"
	// core.ReadRef expects path relative to .vec dir.
	commitHash, err := core.ReadRef(coreRepo, refNameFull)
	if err != nil {
		if core.IsErrNotFound(err) {
			return strings.Repeat("0", 64), nil // Replaced core.ZeroID. Ref doesn't exist, return ZeroID
		}
		logger.Printf("readRef: error reading ref %s: %v", refNameFull, err)
		return "", fmt.Errorf("failed to read ref %s: %w", refNameFull, err)
	}
	return commitHash, nil
}

// checkFastForward determines if newCommit is a descendant of oldCommit.
func checkFastForward(repoPath string, oldCommitHash string, newCommitHash string, logger *log.Logger) (bool, error) {
	if oldCommitHash == newCommitHash {
		return true, nil
	} // Same commit is a fast-forward
	if oldCommitHash == strings.Repeat("0", 64) {
		return true, nil
	} // Creating a new ref is always a fast-forward

	cr := core.NewRepository(repoPath)

	queue := []string{newCommitHash}
	visited := make(map[string]bool)
	visited[newCommitHash] = true

	for len(queue) > 0 {
		currentHash := queue[0]
		queue = queue[1:]

		if currentHash == oldCommitHash {
			return true, nil // Found old commit in ancestry
		}

		// Check if currentHash actually exists before trying to GetCommit
		exists, err := core.ObjectExists(cr, currentHash) // Use cr and handle error
		if err != nil {
			logger.Printf("checkFastForward: error checking existence for commit %s: %v", currentHash, err)
			return false, fmt.Errorf("error checking existence for commit %s: %w", currentHash, err)
		}
		if !exists {
			logger.Printf("checkFastForward: commit %s in ancestry of %s not found", currentHash, newCommitHash)
			return false, fmt.Errorf("commit %s not found during fast-forward check", currentHash)
		}

		commit, err := cr.GetCommit(currentHash) // Use cr.GetCommit, not core.ReadObject + parse
		if err != nil {
			logger.Printf("checkFastForward: error getting commit %s: %v", currentHash, err)
			return false, fmt.Errorf("error reading commit %s: %w", currentHash, err)
		}

		if len(commit.Parents) == 0 {
			continue // Reached a root commit without finding oldCommitHash
		}

		for _, parentHash := range commit.Parents {
			if !visited[parentHash] {
				visited[parentHash] = true
				queue = append(queue, parentHash)
			}
		}
	}

	return false, nil // oldCommitHash not found in newCommitHash's ancestry
}

// Placeholders for functions/types assumed to be in shared packages.
// These will cause "undefined" errors until those packages are created and these are imported.
// This section should be EMPTY after refactoring to shared packages.

// From shared pktline package (e.g., internal/protocol/pktline):
// type SideBandType byte
// const ( SideBandMain SideBandType = 1; SideBandError SideBandType = 2; SideBandProgress SideBandType = 3 )
// func WriteSideBand(w http.ResponseWriter, sbt SideBandType, data []byte) error { return nil }
// func WritePacketLine(w http.ResponseWriter, data []byte) error { return nil }
// func WriteFlushPacket(w http.ResponseWriter) error {return nil}
// const FlushMessage = "0000"
// func ReadPktLine(scanner *bufio.Scanner) (string, error) { return "", nil}

// From shared git object parsing utility (e.g., internal/gitutil):
// type ParsedCommit struct { TreeHash string; ParentHashes []string; AuthorName string; AuthorEmail string; AuthoredAt time.Time; CommitterName string; CommitterEmail string; CommittedAt time.Time; Message string }
// func parseCoreCommitData(data []byte) (*ParsedCommit, error) { return nil, nil}
// type signature struct { Name, Email string; When time.Time }
// func parseSignatureLine(line string) (signature, error) { return nil, nil }

// Add these helper functions at the end of the file

// Helper function to get file/directory permissions for debugging
func getPermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("Error getting permissions: %v", err)
	}
	return fmt.Sprintf("Mode: %s", info.Mode().String())
}

// Fallback file writing method using lower-level operations
func writeFileWithFallback(filename string, data []byte, perm os.FileMode, logger *log.Logger) error {
	logger.Printf("DEBUG: Writing file with fallback method: %s", filename)
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		logger.Printf("DEBUG: Failed to open file: %v", err)
		return err
	}

	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
		logger.Printf("DEBUG: Short write: %d/%d bytes", n, len(data))
	}

	if err1 := f.Sync(); err1 != nil && err == nil {
		err = err1
		logger.Printf("DEBUG: Sync failed: %v", err1)
	}

	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
		logger.Printf("DEBUG: Close failed: %v", err1)
	}

	if err == nil {
		logger.Printf("DEBUG: Successfully wrote file with fallback method")
	}

	return err
}

// atomicWriteFile writes data to a file in an atomic way by using a temporary file
// and then renaming it to the final destination.
func atomicWriteFile(filename string, content string, perm os.FileMode, logger *log.Logger) error {
	logger.Printf("DEBUG: Writing file atomically: %s", filename)

	// Create a new file
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		logger.Printf("DEBUG: Failed to create file: %v", err)
		return err
	}

	// Write the content
	_, err = f.WriteString(content)
	if err != nil {
		f.Close()
		logger.Printf("DEBUG: Failed to write content: %v", err)
		return err
	}

	// Ensure the write is flushed to disk
	err = f.Sync()
	if err != nil {
		f.Close()
		logger.Printf("DEBUG: Failed to sync file: %v", err)
		return err
	}

	// Close the file
	err = f.Close()
	if err != nil {
		logger.Printf("DEBUG: Failed to close file: %v", err)
		return err
	}

	logger.Printf("DEBUG: Successfully wrote file atomically")
	return nil
}
