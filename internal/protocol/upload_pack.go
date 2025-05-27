package protocol

import (
	"bufio"
	// "bytes" // No longer directly needed
	// "encoding/hex" // No longer directly needed
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// "time" // No longer directly needed

	"github.com/NahomAnteneh/vec-server/core"
	"github.com/NahomAnteneh/vec-server/internal/db/models" // For authorize func type
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

const (
	// SideBandDataChunkSize defines the chunk size for sending packfile data over side-band.
	SideBandDataChunkSize = 8192
)

// UploadPackHandler handles the upload-pack protocol endpoint
func UploadPackHandler(repoManager *repository.Manager, logger *log.Logger, authorize func(*http.Request, *models.Repository) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("username")
		repoName := r.PathValue("repo")
		logger.Printf("UPLOAD_PACK: Request for owner=%s, repo=%s", owner, repoName)

		repoPath, err := repoManager.GetRepoPath(owner, repoName)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Invalid repo path for %s/%s: %v", owner, repoName, err)
			http.Error(w, "Invalid repository path", http.StatusBadRequest)
			return
		}
		coreRepo := core.NewRepository(repoPath)

		// Initialize dbRepoModel without OwnerUsername
		dbRepoModel := &models.Repository{Path: repoPath, Name: repoName}
		if err := authorize(r, dbRepoModel); err != nil {
			logger.Printf("UPLOAD_PACK: Authorization failed for %s/%s: %v", owner, repoName, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-vec-upload-pack-result")
		pktLineReader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		clientCaps, wants, haves, shallowCommits, depth, err := parseWantsAndHaves(pktLineReader)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error parsing wants/haves: %v", err)
			http.Error(w, fmt.Sprintf("Error parsing wants and haves: %v", err), http.StatusBadRequest)
			return
		}
		logger.Printf("UPLOAD_PACK: Client capabilities: %s, wants: %v, haves: %v, shallow: %v, depth: %d", clientCaps, wants, haves, shallowCommits, depth)

		for _, wantHash := range wants {
			if !(len(wantHash) == 64 && core.IsValidHex(wantHash)) {
				logger.Printf("UPLOAD_PACK: Invalid want hash: %s", wantHash)
				http.Error(w, fmt.Sprintf("Invalid object hash: %s", wantHash), http.StatusBadRequest)
				return
			}
			objExists, err := core.ObjectExists(coreRepo, wantHash) // Corrected call
			if err != nil {
				logger.Printf("UPLOAD_PACK: Error checking existence for object %s: %v", wantHash, err)
				http.Error(w, "Internal server error checking object", http.StatusInternalServerError)
				return
			}
			if !objExists {
				logger.Printf("UPLOAD_PACK: Wanted object not found: %s", wantHash)
				http.Error(w, fmt.Sprintf("Requested object not found: %s", wantHash), http.StatusNotFound)
				return
			}
		}

		useSideBand := strings.Contains(clientCaps, "side-band") || strings.Contains(clientCaps, "side-band-64k")

		objectHashesToPack, err := determineObjectsToSend(coreRepo, wants, haves, shallowCommits, depth, logger)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error determining objects: %v", err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error determining objects: %v\\n", err)))
			}
			if !useSideBand {
				http.Error(w, "Error determining objects", http.StatusInternalServerError)
			}
			return
		}
		logger.Printf("UPLOAD_PACK: Will attempt to pack %d objects for %s/%s", len(objectHashesToPack), owner, repoName)

		if len(objectHashesToPack) == 0 && len(wants) > 0 {
			response := []byte("NAK\\n")
			if useSideBand {
				if err := WriteSideBand(w, SideBandMain, response); err != nil {
					logger.Printf("UPLOAD_PACK: Error writing NAK: %v", err)
					return
				}
			} else {
				if err := WritePacketLine(w, response); err != nil {
					logger.Printf("UPLOAD_PACK: Error writing NAK: %v", err)
					return
				}
			}
			if err := WriteFlushPacket(w); err != nil {
				logger.Printf("UPLOAD_PACK: Error writing flush after NAK: %v", err)
			}
			logger.Printf("UPLOAD_PACK: Sent NAK for %s/%s as no common objects to send or wants cannot be satisfied now.", owner, repoName)
			return
		} else if len(objectHashesToPack) == 0 && len(wants) == 0 {
			logger.Printf("UPLOAD_PACK: No objects to pack (empty repo or no initial wants). Sending empty pack indication for %s/%s.", owner, repoName)
			if err := WriteFlushPacket(w); err != nil {
				logger.Printf("UPLOAD_PACK: Error writing flush for empty pack: %v", err)
			}
			return
		}

		tempPackfileName := filepath.Join(os.TempDir(), fmt.Sprintf("vec-packfile-%d-%s-%s.pack", os.Getpid(), owner, repoName))
		defer os.Remove(tempPackfileName)

		// packfile.CreateFromObjects expects []string of hashes.
		// The `useDelta` parameter in packfile.CreateFromObjects is the third one.
		if err := packfile.CreateFromObjects(coreRepo, objectHashesToPack, false /*useDelta*/, tempPackfileName); err != nil {
			logger.Printf("UPLOAD_PACK: Error creating packfile for %s/%s: %v", owner, repoName, err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error creating packfile: %v\\n", err)))
			}
			if !useSideBand {
				http.Error(w, "Error creating packfile", http.StatusInternalServerError)
			}
			return
		}

		packfileInfo, err := os.Stat(tempPackfileName)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error stating packfile %s for %s/%s: %v", tempPackfileName, owner, repoName, err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error accessing packfile: %v\\n", err)))
			}
			if !useSideBand {
				http.Error(w, "Error accessing packfile", http.StatusInternalServerError)
			}
			return
		}
		packfileSize := packfileInfo.Size()

		packF, err := os.Open(tempPackfileName)
		if err != nil {
			logger.Printf("UPLOAD_PACK: Error opening packfile %s for %s/%s: %v", tempPackfileName, owner, repoName, err)
			if useSideBand {
				WriteSideBand(w, SideBandError, []byte(fmt.Sprintf("Error opening packfile: %v\\n", err)))
			}
			if !useSideBand {
				http.Error(w, "Error opening packfile", http.StatusInternalServerError)
			}
			return
		}
		defer packF.Close()

		if len(wants) > 0 && len(objectHashesToPack) > 0 {
			ackHash := wants[0]
			foundInPack := false
			for _, pHash := range objectHashesToPack {
				if pHash == ackHash {
					foundInPack = true
					break
				}
			}
			if !foundInPack && len(objectHashesToPack) > 0 {
				ackHash = objectHashesToPack[0]
			}

			ackLine := fmt.Sprintf("ACK %s\\n", ackHash)
			if useSideBand {
				WriteSideBand(w, SideBandMain, []byte(ackLine))
			} else {
				WritePacketLine(w, []byte(ackLine))
			}
		}

		logger.Printf("UPLOAD_PACK: Sending packfile of size %d bytes for %s/%s", packfileSize, owner, repoName)
		if useSideBand {
			if err := sendPackfileWithSideBand(w, packF, packfileSize, logger); err != nil {
				logger.Printf("UPLOAD_PACK: Error sending packfile with sideband for %s/%s: %v", owner, repoName, err)
				return
			}
		} else {
			if err := sendPackfile(w, packF); err != nil {
				logger.Printf("UPLOAD_PACK: Error sending packfile for %s/%s: %v", owner, repoName, err)
				return
			}
		}

		logger.Printf("UPLOAD_PACK: Packfile sent successfully for %s/%s", owner, repoName)
	}
}

// determineObjectsToSend now returns a slice of object hashes ([]string)
func determineObjectsToSend(coreRepo *core.Repository, wants, haves, shallowCommits []string, depth int, logger *log.Logger) ([]string, error) {
	objectsToInclude := make(map[string]struct{}) // Using a map for unique hashes
	visited := make(map[string]bool)              // For graph traversal, to avoid cycles and re-processing

	// TODO: Implement 'depth' and 'shallowCommits' handling for shallow clones more accurately.
	// TODO: Implement proper 'haves' processing to cut off traversal more effectively.

	traversalDepth := 1000000 // Effectively infinite depth for non-shallow fetches
	if depth > 0 {
		traversalDepth = depth // Use client-specified depth for shallow fetches
	}

	for _, wantHash := range wants {
		if err := addHashedObjectToInclude(coreRepo, wantHash, objectsToInclude, visited, logger, traversalDepth, haves); err != nil {
			// If a specific want cannot be processed, it might be an error from reading/parsing an existing object.
			// ObjectExists check in UploadPackHandler should have caught initially missing `wants`.
			return nil, fmt.Errorf("processing wanted object %s: %w", wantHash, err)
		}
	}

	hashes := make([]string, 0, len(objectsToInclude))
	for hash := range objectsToInclude {
		hashes = append(hashes, hash)
	}
	logger.Printf("determineObjectsToSend: collected %d unique object hashes to pack.", len(hashes))
	return hashes, nil
}

// addHashedObjectToInclude adds an object's hash and its dependencies' hashes to the set if not already visited.
// It also considers the 'haves' list to stop traversal for those specific objects.
func addHashedObjectToInclude(coreRepo *core.Repository, hash string, objectsToInclude map[string]struct{}, visited map[string]bool, logger *log.Logger, depthRemaining int, clientHaves []string) error {
	if visited[hash] || depthRemaining <= 0 {
		return nil
	}

	// Basic check against clientHaves: if client has this object, don't process it further from this path.
	for _, haveHash := range clientHaves {
		if hash == haveHash {
			visited[hash] = true // Mark as visited (effectively, client has it)
			// logger.Printf("DEBUG: Object %s is in clientHaves, skipping.", hash)
			return nil
		}
	}

	visited[hash] = true // Mark current object as visited for this traversal path

	// Ensure object exists before attempting to read its type or include it.
	// This is important for objects discovered during traversal.
	exists, err := core.ObjectExists(coreRepo, hash)
	if err != nil {
		return fmt.Errorf("checking existence for object %s during traversal: %w", hash, err)
	}
	if !exists {
		logger.Printf("Warning: Object %s (dependency) not found during pack graph traversal.", hash)
		return nil // Don't error out, just skip this missing dependency.
	}

	// Add the current object's hash to the include list
	objectsToInclude[hash] = struct{}{}
	// logger.Printf("DEBUG: Including object %s", hash)

	// Use ReadObject to get the type, as ReadObjectHeader was hypothetical
	objTypeString, _, err := coreRepo.ReadObject(hash) // We only need the type string here
	if err != nil {
		if core.IsErrNotFound(err) { // Should be caught by ObjectExists, but defensive check
			logger.Printf("Warning: Object %s (type %s) not found after existence check.", hash, objTypeString)
			return nil
		}
		return fmt.Errorf("reading object %s to determine type for traversal: %w", hash, err)
	}

	// Recursively add dependencies based on object type
	currentCommitTraversalDepth := depthRemaining
	if objTypeString == "commit" {
		// For commits, decrement depth if it's a finite depth traversal.
		if depthRemaining > 0 && depthRemaining != 1000000 { // Avoid decrementing "infinite" depth
			currentCommitTraversalDepth--
		}

		coreCommit, errGetCommit := coreRepo.GetCommit(hash)
		if errGetCommit != nil {
			logger.Printf("Warning: Failed to get commit details for %s: %v. Will not traverse its parents/tree.", hash, errGetCommit)
			return nil // Do not propagate error, just log and skip dependencies of this broken commit.
		}

		// Tree and its contents are always included fully if the commit is included (infinite depth for tree part).
		if err := addHashedObjectToInclude(coreRepo, coreCommit.Tree, objectsToInclude, visited, logger, 1000000, clientHaves); err != nil {
			logger.Printf("Warning: Failed to process tree %s for commit %s: %v", coreCommit.Tree, hash, err)
			// Continue even if tree processing has issues for robustness
		}
		for _, parentHash := range coreCommit.Parents {
			if err := addHashedObjectToInclude(coreRepo, parentHash, objectsToInclude, visited, logger, currentCommitTraversalDepth, clientHaves); err != nil {
				logger.Printf("Warning: Failed to process parent %s for commit %s: %v", parentHash, hash, err)
				// Continue
			}
		}
	} else if objTypeString == "tree" {
		coreTree, errGetTree := coreRepo.GetTree(hash)
		if errGetTree != nil {
			logger.Printf("Warning: Failed to get tree details for %s: %v. Will not traverse its entries.", hash, errGetTree)
			return nil // Log and skip entries
		}
		for _, entry := range coreTree.Entries {
			// Tree entries (blobs or sub-trees) are always included fully.
			if err := addHashedObjectToInclude(coreRepo, entry.Hash, objectsToInclude, visited, logger, 1000000, clientHaves); err != nil {
				logger.Printf("Warning: Failed to process tree entry %s (obj %s) for tree %s: %v", entry.Name, entry.Hash, hash, err)
				// Continue
			}
		}
	}
	// Blobs and Tags (if tags were simple objects and added to objectsToInclude) have no further dependencies traversed from here.
	return nil
}

// parseWantsAndHaves parses the client's want/have list.
// Simplified: does not handle multi_ack, multi_ack_detailed, or complex capabilities yet.
func parseWantsAndHaves(reader io.Reader) (clientCaps string, wants []string, haves []string, shallowCommits []string, depth int, err error) {
	br := bufio.NewReader(reader)
	firstLine := true
	maxRequests := 1000

	for i := 0; i < maxRequests; i++ {
		line, readErr := ReadPktLineFromReader(br)
		if readErr == io.EOF {
			if firstLine && line == "" {
				return "", nil, nil, nil, 0, nil
			}
			break
		}
		if readErr != nil {
			return "", nil, nil, nil, 0, fmt.Errorf("reading pkt-line: %w", readErr)
		}

		line = strings.TrimSuffix(line, "\\n")
		if line == "done" {
			break
		}
		if line == FlushPkt {
			break
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		var hashValue string
		if len(parts) > 1 {
			hashValue = parts[1]
		}

		if firstLine {
			if command != "want" || len(hashValue) != 64 {
				return "", nil, nil, nil, 0, fmt.Errorf("protocol error: first want line invalid: %s", line)
			}
			wants = append(wants, hashValue)
			if len(parts) > 2 {
				clientCaps = strings.Join(parts[2:], " ")
			}
			firstLine = false
		} else {
			switch command {
			case "want":
				if len(hashValue) != 64 {
					return "", nil, nil, nil, 0, fmt.Errorf("protocol error: invalid want hash: %s", hashValue)
				}
				wants = append(wants, hashValue)
			case "have":
				if len(hashValue) != 64 {
					return "", nil, nil, nil, 0, fmt.Errorf("protocol error: invalid have hash: %s", hashValue)
				}
				haves = append(haves, hashValue)
			case "shallow":
				if len(hashValue) != 64 {
					return "", nil, nil, nil, 0, fmt.Errorf("protocol error: invalid shallow hash: %s", hashValue)
				}
				shallowCommits = append(shallowCommits, hashValue)
			case "depth":
				d, parseErr := strconv.Atoi(hashValue)
				if parseErr != nil || d < 0 {
					return "", nil, nil, nil, 0, fmt.Errorf("protocol error: invalid depth value: %s", hashValue)
				}
				depth = d
			default:
			}
		}
	}
	if firstLine && len(wants) == 0 {
		return "", nil, nil, nil, 0, fmt.Errorf("protocol error: no want lines received")
	}

	return clientCaps, wants, haves, shallowCommits, depth, nil
}

// sendPackfile sends the packfile data directly to the client.
func sendPackfile(w http.ResponseWriter, packfileReader io.Reader) error {
	_, err := io.Copy(w, packfileReader)
	if err != nil {
		return fmt.Errorf("copying packfile to response: %w", err)
	}
	return nil
}

// sendPackfileWithSideBand sends the packfile data multiplexed with side-band.
func sendPackfileWithSideBand(w http.ResponseWriter, packfileReader io.Reader, packfileSize int64, logger *log.Logger) error {
	progStartMsg := fmt.Sprintf("Counting objects: %d (packfile size guess)", packfileSize)
	WriteSideBand(w, SideBandProgress, []byte(progStartMsg))

	buf := make([]byte, SideBandDataChunkSize)
	for {
		n, err := packfileReader.Read(buf)
		if n > 0 {
			if wErr := WriteSideBand(w, SideBandMain, buf[:n]); wErr != nil {
				return fmt.Errorf("writing pack data to sideband: %w", wErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading packfile for sideband: %w", err)
		}
	}

	progDoneMsg := "Done."
	WriteSideBand(w, SideBandProgress, []byte(progDoneMsg))

	return WriteFlushPacket(w)
}

// ReadPktLineFromReader reads a single pkt-line from a reader.
func ReadPktLineFromReader(reader *bufio.Reader) (string, error) {
	lenHex := make([]byte, 4)
	_, err := io.ReadFull(reader, lenHex)
	if err == io.EOF {
		return "", io.EOF
	}
	if err != nil {
		return "", fmt.Errorf("reading pkt-line length: %w", err)
	}

	length, err := strconv.ParseInt(string(lenHex), 16, 32)
	if err != nil {
		return "", fmt.Errorf("parsing pkt-line length '%s': %w", string(lenHex), err)
	}

	if length == 0 {
		return FlushPkt, nil
	}
	if length < 4 {
		return "", fmt.Errorf("invalid pkt-line length: %d", length)
	}
	dataBytes := make([]byte, length-4)
	_, err = io.ReadFull(reader, dataBytes)
	if err != nil {
		return "", fmt.Errorf("reading pkt-line data (len %d): %w", length-4, err)
	}
	return string(dataBytes), nil
}

// ReadPktLine is a utility function.
func ReadPktLine(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("scanning pkt-line: %w", err)
		}
		return "", io.EOF
	}
	line := scanner.Text()
	if len(line) == 4 && (line == "0000" || line == FlushPkt) {
		return FlushPkt, nil
	}
	return line, nil
}
