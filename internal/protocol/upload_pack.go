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
	"strconv"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/objects"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// Object type constants for internal use
const (
	TypeCommit = objects.ObjectTypeCommit
	TypeTree   = objects.ObjectTypeTree
	TypeBlob   = objects.ObjectTypeBlob
)

// UploadPackHandler handles the upload-pack protocol endpoint (used for clone/fetch)
func UploadPackHandler(repoManager *repository.Manager) http.HandlerFunc {
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
		w.Header().Set("Content-Type", "application/x-vec-upload-pack-result")

		// Create buffered reader for request body
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		// Parse client's wants and haves
		clientCaps, wants, haves, shallowCommits, depth, err := parseWantsAndHaves(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing wants and haves: %v", err), http.StatusBadRequest)
			return
		}

		// Log client request info
		log.Printf("Client capabilities: %s", clientCaps)
		log.Printf("Client wants: %v", wants)
		log.Printf("Client has: %v", haves)
		log.Printf("Shallow: %v", shallowCommits)
		log.Printf("Depth: %d", depth)

		// Check if we have the requested objects
		objectsPath := filepath.Join(repoPath, ".vec", "objects")
		storage := objects.NewStorage(objectsPath)

		// Validate that the wanted objects exist
		for _, want := range wants {
			// Check if object exists by attempting to get it
			_, err := storage.GetObject(want)
			if err != nil {
				http.Error(w, fmt.Sprintf("Requested object not found: %s", want), http.StatusNotFound)
				return
			}
		}

		// Determine if side-band is supported
		useSideBand := false
		for _, cap := range strings.Split(clientCaps, " ") {
			if cap == "side-band" || cap == "side-band-64k" {
				useSideBand = true
				break
			}
		}

		// Determine which objects the client needs
		objectsToSend, err := determineObjectsToSend(repoPath, storage, wants, haves, shallowCommits, depth)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error determining objects to send: %v", err), http.StatusInternalServerError)
			return
		}

		// If the client has all objects, we're done
		if len(objectsToSend) == 0 {
			if useSideBand {
				// Send acknowledgement with side-band
				if err := WriteSideBand(w, SideBandMain, []byte("NAK\n")); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}

				// Send flush packet
				if err := WriteFlushPacket(w); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			} else {
				// Send acknowledgement without side-band
				if err := WritePacketLine(w, []byte("NAK\n")); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}

				// Send flush packet
				if err := WriteFlushPacket(w); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			}
			return
		}

		// Create temporary file for packfile
		packfilePath := filepath.Join(os.TempDir(), fmt.Sprintf("vec-packfile-%d", os.Getpid()))
		defer os.Remove(packfilePath)

		// Create packfile
		err = createPackfile(repoPath, objectsToSend, packfilePath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating packfile: %v", err), http.StatusInternalServerError)
			return
		}

		// Open the packfile for reading
		packfile, err := os.Open(packfilePath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error opening packfile: %v", err), http.StatusInternalServerError)
			return
		}
		defer packfile.Close()

		// Get packfile size
		packfileStat, err := packfile.Stat()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting packfile size: %v", err), http.StatusInternalServerError)
			return
		}

		// Send ACK for the first have (or NAK if none)
		if len(haves) > 0 {
			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, []byte(fmt.Sprintf("ACK %s\n", haves[0]))); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			} else {
				if err := WritePacketLine(w, []byte(fmt.Sprintf("ACK %s\n", haves[0]))); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			}
		} else {
			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, []byte("NAK\n")); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			} else {
				if err := WritePacketLine(w, []byte("NAK\n")); err != nil {
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			}
		}

		// Send packfile
		if useSideBand {
			sendPackfileWithSideBand(w, packfile, packfileStat.Size())
		} else {
			sendPackfile(w, packfile)
		}
	}
}

// parseWantsAndHaves parses the client's wants and haves from the request body
func parseWantsAndHaves(reader io.Reader) (string, []string, []string, []string, int, error) {
	var (
		wants          []string
		haves          []string
		shallowCommits []string
		clientCaps     string
		depth          int
		firstWant      bool = true
	)

	for {
		data, isFlush, err := ReadPacketLine(reader)
		if err != nil {
			return "", nil, nil, nil, 0, err
		}

		// End of commands
		if isFlush {
			break
		}

		line := string(bytes.TrimSpace(data))

		if strings.HasPrefix(line, "want ") {
			if firstWant {
				// First want line may include capabilities
				wantLine, caps := ParseCapabilities(line[5:]) // Skip "want " prefix
				wants = append(wants, wantLine)
				clientCaps = caps
				firstWant = false
			} else {
				// Subsequent want lines
				hash := strings.TrimPrefix(line, "want ")
				wants = append(wants, hash)
			}
		} else if strings.HasPrefix(line, "have ") {
			hash := strings.TrimPrefix(line, "have ")
			haves = append(haves, hash)
		} else if strings.HasPrefix(line, "shallow ") {
			hash := strings.TrimPrefix(line, "shallow ")
			shallowCommits = append(shallowCommits, hash)
		} else if strings.HasPrefix(line, "deepen ") {
			depthStr := strings.TrimPrefix(line, "deepen ")
			var err error
			depth, err = strconv.Atoi(depthStr)
			if err != nil {
				return "", nil, nil, nil, 0, fmt.Errorf("invalid deepen value: %s", depthStr)
			}
		} else if line == "done" {
			// Client indicates the end of the request
			break
		}
	}

	return clientCaps, wants, haves, shallowCommits, depth, nil
}

// determineObjectsToSend determines which objects to send to the client
func determineObjectsToSend(repoPath string, storage *objects.Storage, wants, haves, shallow []string, depth int) ([]string, error) {
	// First, we need to find all objects reachable from the wants
	wantedObjects := make(map[string]bool)

	for _, want := range wants {
		// Get all objects reachable from the want
		reachable, err := getReachableObjects(storage, want, depth, shallow)
		if err != nil {
			return nil, err
		}

		// Add all reachable objects
		for _, hash := range reachable {
			wantedObjects[hash] = true
		}
	}

	// Remove objects that the client already has
	for _, have := range haves {
		// Only consider objects that the client actually has
		_, err := storage.GetObject(have)
		if err != nil {
			continue
		}

		// Remove the object itself
		delete(wantedObjects, have)

		// Get all objects reachable from this have
		reachable, err := getReachableObjects(storage, have, 0, nil)
		if err != nil {
			continue
		}

		// Remove all objects reachable from the have
		for _, hash := range reachable {
			delete(wantedObjects, hash)
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(wantedObjects))
	for hash := range wantedObjects {
		result = append(result, hash)
	}

	return result, nil
}

// getReachableObjects gets all objects reachable from the given object
func getReachableObjects(storage *objects.Storage, startHash string, depth int, shallow []string) ([]string, error) {
	reachable := make(map[string]bool)

	// Helper function to check if a commit is in the shallow list
	isShallow := func(hash string) bool {
		for _, s := range shallow {
			if s == hash {
				return true
			}
		}
		return false
	}

	// Process all reachable objects starting from startHash
	toProcess := []string{startHash}
	processedCommits := make(map[string]int) // Map commit hash to depth

	for len(toProcess) > 0 {
		hash := toProcess[0]
		toProcess = toProcess[1:]

		// Skip if already processed
		if reachable[hash] {
			continue
		}

		// Mark as reachable
		reachable[hash] = true

		// Get the object
		obj, err := storage.GetObject(hash)
		if err != nil {
			return nil, err
		}

		// Process based on object type
		switch obj.Type {
		case TypeCommit:
			// Check depth limit
			currentDepth := processedCommits[hash]
			if depth > 0 && currentDepth >= depth {
				continue
			}

			// Skip further processing if this commit is in the shallow list
			if isShallow(hash) {
				continue
			}

			// Get parent commits
			parentHashes := extractParentCommits(obj.Content)
			for _, parentHash := range parentHashes {
				if !reachable[parentHash] {
					toProcess = append(toProcess, parentHash)
					processedCommits[parentHash] = currentDepth + 1
				}
			}

			// Get tree
			treeHash := extractTreeHash(obj.Content)
			if treeHash != "" && !reachable[treeHash] {
				toProcess = append(toProcess, treeHash)
			}
		case TypeTree:
			// Get all entries in the tree
			entries := extractTreeEntries(obj.Content)
			for _, entry := range entries {
				if !reachable[entry] {
					toProcess = append(toProcess, entry)
				}
			}
		case TypeBlob:
			// Blobs don't reference other objects
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(reachable))
	for hash := range reachable {
		result = append(result, hash)
	}

	return result, nil
}

// extractParentCommits extracts parent commit hashes from commit data
func extractParentCommits(data []byte) []string {
	var parents []string
	lines := bytes.Split(data, []byte{'\n'})

	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("parent ")) {
			parent := string(bytes.TrimPrefix(line, []byte("parent ")))
			parents = append(parents, parent)
		}
	}

	return parents
}

// extractTreeHash extracts the tree hash from commit data
func extractTreeHash(data []byte) string {
	lines := bytes.Split(data, []byte{'\n'})

	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("tree ")) {
			return string(bytes.TrimPrefix(line, []byte("tree ")))
		}
	}

	return ""
}

// extractTreeEntries extracts object hashes from tree data
func extractTreeEntries(data []byte) []string {
	var entries []string

	// Simple parser for tree objects
	// Format: <mode> <name>\0<hash>
	i := 0
	for i < len(data) {
		// Skip the mode and name
		nullPos := bytes.IndexByte(data[i:], 0)
		if nullPos == -1 {
			break
		}

		i += nullPos + 1

		// Extract the hash (20 bytes)
		if i+20 <= len(data) {
			hash := fmt.Sprintf("%x", data[i:i+20])
			entries = append(entries, hash)
			i += 20
		} else {
			break
		}
	}

	return entries
}

// createPackfile creates a packfile containing the specified objects
func createPackfile(repoPath string, objectIDs []string, outputPath string) error {
	// Get object storage

	// Open output file
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create packfile: %w", err)
	}
	defer output.Close()

	// Collect objects from storage
	objectsToPack := make([]packfile.Object, 0, len(objectIDs))
	for _, id := range objectIDs {
		objTypeStr, objData, err := objects.ReadObject(repoPath, id)
		if err != nil {
			return fmt.Errorf("failed to read object %s: %w", id, err)
		}
		// Convert string type to packfile.ObjectType
		var objType packfile.ObjectType
		switch objTypeStr {
		case "commit":
			objType = packfile.OBJ_COMMIT
		case "tree":
			objType = packfile.OBJ_TREE
		case "blob":
			objType = packfile.OBJ_BLOB
		case "tag":
			objType = packfile.OBJ_TAG
		default:
			// Handle unknown type, maybe skip or return error
			log.Printf("Warning: Unknown object type '%s' for object %s. Skipping.", objTypeStr, id)
			continue
		}

		// Create packfile.Object
		objectsToPack = append(objectsToPack, packfile.Object{
			Hash: id, // Use the ID as the hash
			Type: objType,
			Data: objData, // Use the data read from storage
		})
	}

	// Create the modern packfile with collected objects and delta compression
	err = packfile.CreateModernPackfile(objectsToPack, outputPath)
	if err != nil {
		return fmt.Errorf("failed to create modern packfile: %w", err)
	}

	return nil
}

// sendPackfile sends a packfile without side-band encoding
func sendPackfile(w http.ResponseWriter, packfile io.Reader) error {
	// Copy packfile to response
	if _, err := io.Copy(w, packfile); err != nil {
		return err
	}

	// End with flush packet
	return WriteFlushPacket(w)
}

// sendPackfileWithSideBand sends a packfile with side-band encoding
func sendPackfileWithSideBand(w http.ResponseWriter, packfile io.Reader, packfileSize int64) error {
	// Buffer for reading
	buf := make([]byte, 8192)
	var totalSent int64

	// Send packfile data on channel 1
	for {
		n, err := packfile.Read(buf)
		if n > 0 {
			if err := WriteSideBand(w, SideBandMain, buf[:n]); err != nil {
				return err
			}
			totalSent += int64(n)

			// Send progress every 100KB
			if totalSent%102400 < 8192 {
				progressMsg := fmt.Sprintf("Sending packfile: %.1f%% (%d/%d)",
					float64(totalSent)/float64(packfileSize)*100,
					totalSent, packfileSize)
				if err := WriteSideBand(w, SideBandProgress, []byte(progressMsg)); err != nil {
					// Progress errors are non-fatal
					log.Printf("Error sending progress: %v", err)
				}
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}
	}

	// Send completion message
	if err := WriteSideBand(w, SideBandProgress, []byte("Packfile sent successfully")); err != nil {
		// Progress errors are non-fatal
		log.Printf("Error sending completion message: %v", err)
	}

	// End with flush packet
	return WriteFlushPacket(w)
}
