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

	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/objects"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// UploadPackHandler handles the upload-pack protocol endpoint
func UploadPackHandler(repoManager *repository.Manager, logger *log.Logger, authorize func(*http.Request, *models.Repository) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("username")
		repoName := r.PathValue("repo")
		logger.Printf("UPLOAD_PACK: Request for owner=%s, repo=%s", owner, repoName)

		exists, err := repoManager.RepositoryExists(owner, repoName)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error checking repository: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !exists {
			logger.Printf("UPLOAD_PACK: Repository not found: owner=%s, repo=%s", owner, repoName)
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		repoPath, err := repoManager.GetRepoPath(owner, repoName)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Invalid repo path: %v", err)
			http.Error(w, "Invalid repository path", http.StatusBadRequest)
			return
		}
		repo := &models.Repository{Path: repoPath}

		if err := authorize(r, repo); err != nil {
			logger.Printf("UPLOAD_PACK: Authorization failed: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-vec-upload-pack-result")
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		clientCaps, wants, haves, shallowCommits, depth, err := parseWantsAndHaves(reader)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error parsing wants/haves: %v", err)
			http.Error(w, fmt.Sprintf("Error parsing wants and haves: %v", err), http.StatusBadRequest)
			return
		}
		logger.Printf("UPLOAD_PACK: Client capabilities: %s, wants: %v, haves: %v, shallow: %v, depth: %d", clientCaps, wants, haves, shallowCommits, depth)

		objectsPath := filepath.Join(repoPath, ".vec", "objects")
		storage := objects.NewStorage(objectsPath)

		for _, want := range wants {
			if !isValidCommitHash(want) {
				logger.Printf("UPLOAD_PACK: Invalid want hash: %s", want)
				http.Error(w, fmt.Sprintf("Invalid object hash: %s", want), http.StatusBadRequest)
				return
			}
			if _, err := storage.GetObject(want); err != nil {
				logger.Printf("UPLOAD_PACK: Object not found: %s", want)
				http.Error(w, fmt.Sprintf("Requested object not found: %s", want), http.StatusNotFound)
				return
			}
		}

		useSideBand := strings.Contains(clientCaps, "side-band") || strings.Contains(clientCaps, "side-band-64k")
		objectsToSend, err := determineObjectsToSend(repoPath, storage, wants, haves, shallowCommits, depth)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error determining objects: %v", err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error determining objects: %v\n", err)))
			}
			http.Error(w, "Error determining objects", http.StatusInternalServerError)
			return
		}
		logger.Printf("UPLOAD_PACK: Sending %d objects", len(objectsToSend))

		if len(objectsToSend) == 0 {
			response := []byte("NAK\n")
			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, response); err != nil {
					logger.Printf("UPLOAD_PACK: Error writing NAK: %v", err)
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			} else {
				if err := WritePacketLine(w, response); err != nil {
					logger.Printf("UPLOAD_PACK: Error writing NAK: %v", err)
					http.Error(w, "Error writing response", http.StatusInternalServerError)
					return
				}
			}
			if err := WriteFlushPacket(w); err != nil {
				logger.Printf("UPLOAD_PACK: Error writing flush: %v", err)
			}
			return
		}

		packfilePath := filepath.Join(os.TempDir(), fmt.Sprintf("vec-packfile-%d", os.Getpid()))
		defer os.Remove(packfilePath)

		if err := createPackfile(repoPath, objectsToSend, packfilePath); err != nil {
			logger.Printf("UPLOAD_PACK: Error creating packfile: %v", err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error creating packfile: %v\n", err)))
			}
			http.Error(w, "Error creating packfile", http.StatusInternalServerError)
			return
		}

		packfile, err := os.Open(packfilePath)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error opening packfile: %v", err)
			http.Error(w, "Error opening packfile", http.StatusInternalServerError)
			return
		}
		defer packfile.Close()

		packfileStat, err := packfile.Stat()
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error getting packfile size: %v", err)
			http.Error(w, "Error getting packfile size", http.StatusInternalServerError)
			return
		}

		response := []byte("NAK\n")
		if len(haves) > 0 {
			response = []byte(fmt.Sprintf("ACK %s\n", haves[0]))
		}
		if useSideBand {
			if err := WriteSideBand(w, SideBandMain, response); err != nil {
				logger.Printf("UPLOAD_PACK: Error writing ACK/NAK: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
		} else {
			if err := WritePacketLine(w, response); err != nil {
				logger.Printf("UPLOAD_PACK: Error writing ACK/NAK: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
		}

		if useSideBand {
			if err := sendPackfileWithSideBand(w, packfile, packfileStat.Size(), logger); err != nil {
				logger.Printf("UPLOAD_PACK: Error sending packfile: %v", err)
				http.Error(w, "Error sending packfile", http.StatusInternalServerError)
				return
			}
		} else {
			if err := sendPackfile(w, packfile); err != nil {
				logger.Printf("UPLOAD_PACK: Error sending packfile: %v", err)
				http.Error(w, "Error sending packfile", http.StatusInternalServerError)
				return
			}
		}

		logger.Printf("UPLOAD_PACK: Completed request for %s/%s", owner, repoName)
	}
}

// parseWantsAndHaves parses the client's wants and haves
func parseWantsAndHaves(reader io.Reader) (string, []string, []string, []string, int, error) {
	var wants, haves, shallowCommits []string
	var clientCaps string
	var depth int
	firstWant := true

	for {
		data, isFlush, err := ReadPacketLine(reader)
		if err != nil {
			return "", nil, nil, nil, 0, fmt.Errorf("failed to read packet: %w", err)
		}
		if isFlush {
			break
		}

		line := string(bytes.TrimSpace(data))
		if strings.HasPrefix(line, "want ") {
			hash := strings.TrimPrefix(line, "want ")
			if firstWant {
				wantLine, caps := ParseCapabilities(hash)
				if !isValidCommitHash(wantLine) {
					return "", nil, nil, nil, 0, fmt.Errorf("invalid want hash: %s", wantLine)
				}
				wants = append(wants, wantLine)
				clientCaps = caps
				firstWant = false
			} else {
				if !isValidCommitHash(hash) {
					return "", nil, nil, nil, 0, fmt.Errorf("invalid want hash: %s", hash)
				}
				wants = append(wants, hash)
			}
		} else if strings.HasPrefix(line, "have ") {
			hash := strings.TrimPrefix(line, "have ")
			if !isValidCommitHash(hash) {
				continue // Skip invalid hashes
			}
			haves = append(haves, hash)
		} else if strings.HasPrefix(line, "shallow ") {
			hash := strings.TrimPrefix(line, "shallow ")
			if !isValidCommitHash(hash) {
				return "", nil, nil, nil, 0, fmt.Errorf("invalid shallow hash: %s", hash)
			}
			shallowCommits = append(shallowCommits, hash)
		} else if strings.HasPrefix(line, "deepen ") {
			depthStr := strings.TrimPrefix(line, "deepen ")
			if depth, err = strconv.Atoi(depthStr); err != nil {
				return "", nil, nil, nil, 0, fmt.Errorf("invalid deepen value: %s", depthStr)
			}
		} else if line == "done" {
			break
		}
	}

	return clientCaps, wants, haves, shallowCommits, depth, nil
}

// determineObjectsToSend determines which objects to send
func determineObjectsToSend(repoPath string, storage *objects.Storage, wants, haves, shallow []string, depth int) ([]string, error) {
	wantedObjects := make(map[string]bool)
	for _, want := range wants {
		reachable, err := getReachableObjects(storage, want, depth, shallow)
		if err != nil {
			return nil, fmt.Errorf("failed to get reachable objects for %s: %w", want, err)
		}
		for _, hash := range reachable {
			wantedObjects[hash] = true
		}
	}

	for _, have := range haves {
		if _, err := storage.GetObject(have); err != nil {
			continue
		}
		delete(wantedObjects, have)
		reachable, err := getReachableObjects(storage, have, 0, nil)
		if err != nil {
			continue
		}
		for _, hash := range reachable {
			delete(wantedObjects, hash)
		}
	}

	result := make([]string, 0, len(wantedObjects))
	for hash := range wantedObjects {
		result = append(result, hash)
	}
	return result, nil
}

// getReachableObjects gets all objects reachable from a start hash
func getReachableObjects(storage *objects.Storage, startHash string, depth int, shallow []string) ([]string, error) {
	reachable := make(map[string]bool)
	isShallow := func(hash string) bool {
		for _, s := range shallow {
			if s == hash {
				return true
			}
		}
		return false
	}

	toProcess := []string{startHash}
	processedCommits := make(map[string]int)

	for len(toProcess) > 0 {
		hash := toProcess[0]
		toProcess = toProcess[1:]
		if reachable[hash] {
			continue
		}
		reachable[hash] = true

		obj, err := storage.GetObject(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to get object %s: %w", hash, err)
		}

		switch obj.Type {
		case objects.ObjectTypeCommit:
			currentDepth := processedCommits[hash]
			if depth > 0 && currentDepth >= depth {
				continue
			}
			if isShallow(hash) {
				continue
			}
			for _, parentHash := range extractParentCommits(obj.Content) {
				if !isValidCommitHash(parentHash) {
					continue
				}
				if !reachable[parentHash] {
					toProcess = append(toProcess, parentHash)
					processedCommits[parentHash] = currentDepth + 1
				}
			}
			if treeHash := extractTreeHash(obj.Content); treeHash != "" && !reachable[treeHash] {
				if isValidCommitHash(treeHash) {
					toProcess = append(toProcess, treeHash)
				}
			}
		case objects.ObjectTypeTree:
			for _, entry := range extractTreeEntries(obj.Content) {
				if isValidCommitHash(entry) && !reachable[entry] {
					toProcess = append(toProcess, entry)
				}
			}
		case objects.ObjectTypeBlob:
			// No further processing
		}
	}

	result := make([]string, 0, len(reachable))
	for hash := range reachable {
		result = append(result, hash)
	}
	return result, nil
}

// extractParentCommits extracts parent commit hashes
func extractParentCommits(data []byte) []string {
	var parents []string
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("parent ")) {
			parents = append(parents, string(bytes.TrimPrefix(line, []byte("parent "))))
		}
	}
	return parents
}

// extractTreeHash extracts the tree hash
func extractTreeHash(data []byte) string {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("tree ")) {
			return string(bytes.TrimPrefix(line, []byte("tree ")))
		}
	}
	return ""
}

// extractTreeEntries extracts object hashes from tree data
func extractTreeEntries(data []byte) []string {
	var entries []string
	i := 0
	for i < len(data) {
		nullPos := bytes.IndexByte(data[i:], 0)
		if nullPos == -1 {
			break
		}
		i += nullPos + 1
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

// createPackfile creates a packfile for the specified objects
func createPackfile(repoPath string, objectIDs []string, outputPath string) error {
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create packfile %s: %w", outputPath, err)
	}
	defer output.Close()

	objectsToPack := make([]packfile.Object, 0, len(objectIDs))
	for _, id := range objectIDs {
		objTypeStr, objData, err := objects.ReadObject(repoPath, id)
		if err != nil {
			return fmt.Errorf("failed to read object %s: %w", id, err)
		}
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
			continue
		}
		objectsToPack = append(objectsToPack, packfile.Object{
			Hash: id,
			Type: objType,
			Data: objData,
		})
	}

	if err := packfile.CreateModernPackfile(objectsToPack, outputPath); err != nil {
		return fmt.Errorf("failed to create packfile %s: %w", outputPath, err)
	}
	return nil
}

// sendPackfile sends a packfile without side-band
func sendPackfile(w http.ResponseWriter, packfile io.Reader) error {
	if _, err := io.Copy(w, packfile); err != nil {
		return fmt.Errorf("failed to send packfile: %w", err)
	}
	return WriteFlushPacket(w)
}

// sendPackfileWithSideBand sends a packfile with side-band encoding
func sendPackfileWithSideBand(w http.ResponseWriter, packfile io.Reader, packfileSize int64, logger *log.Logger) error {
	buf := make([]byte, 8192)
	var totalSent int64

	for {
		n, err := packfile.Read(buf)
		if n > 0 {
			if err := WriteSideBand(w, SideBandMain, buf[:n]); err != nil {
				return fmt.Errorf("failed to send packfile data: %w", err)
			}
			totalSent += int64(n)
			if totalSent%102400 < 8192 {
				progressMsg := fmt.Sprintf("Sending packfile: %.1f%% (%d/%d)\n", float64(totalSent)/float64(packfileSize)*100, totalSent, packfileSize)
				if err := WriteSideBand(w, SideBandProgress, []byte(progressMsg)); err != nil {
					logger.Printf("UPLOAD_PACK: Error sending progress: %v", err)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read packfile: %w", err)
		}
	}

	if err := WriteSideBand(w, SideBandProgress, []byte("Packfile sent successfully\n")); err != nil {
		logger.Printf("UPLOAD_PACK: Error sending completion: %v", err)
	}
	return WriteFlushPacket(w)
}
