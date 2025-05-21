package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/objects"
	"github.com/NahomAnteneh/vec-server/internal/packfile"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// UploadPackHandler handles the upload-pack protocol endpoint (used for clone/fetch)
func UploadPackHandler(repoManager *repository.Manager) http.HandlerFunc {
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
		w.Header().Set("Content-Type", "application/x-vec-upload-pack-result")

		// Create buffered reader for request body
		reader := bufio.NewReader(r.Body)
		defer r.Body.Close()

		// Parse client's wants and haves
		wants, haves, depth, err := parseWantsAndHaves(reader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error parsing wants and haves: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("Client wants: %v", wants)
		log.Printf("Client has: %v", haves)
		log.Printf("Depth: %d", depth)

		// Determine which objects the client needs
		objectsToSend, err := determineObjectsToSend(repoPath, wants, haves, depth)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error determining objects to send: %v", err), http.StatusInternalServerError)
			return
		}

		// Create packfile
		packfileData, err := createPackfile(repoPath, objectsToSend)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating packfile: %v", err), http.StatusInternalServerError)
			return
		}

		// Send packfile to client with side-band encoding if supported
		if supportsSideBand(r) {
			sendPackfileWithSideBand(w, packfileData)
		} else {
			w.Write(packfileData)
		}
	}
}

// parseWantsAndHaves parses the client's wants and haves from the request body
func parseWantsAndHaves(reader io.Reader) ([]string, []string, int, error) {
	var wants, haves []string
	depth := 0

	for {
		data, isFlush, err := ReadPacketLine(reader)
		if err != nil {
			return nil, nil, 0, err
		}

		// End of commands
		if isFlush {
			break
		}

		line := string(data)
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "want ") {
			hash := strings.TrimPrefix(line, "want ")
			hash = strings.Split(hash, " ")[0] // Remove capabilities if present
			wants = append(wants, hash)
		} else if strings.HasPrefix(line, "have ") {
			hash := strings.TrimPrefix(line, "have ")
			haves = append(haves, hash)
		} else if strings.HasPrefix(line, "deepen ") {
			_, err := fmt.Sscanf(line, "deepen %d", &depth)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("invalid deepen line: %s", line)
			}
		}
	}

	return wants, haves, depth, nil
}

// determineObjectsToSend determines which objects to send to the client
func determineObjectsToSend(repoPath string, wants, haves []string, depth int) ([]string, error) {
	// In a real implementation, this would:
	// 1. Find all objects reachable from the wants
	// 2. Exclude objects reachable from the haves
	// 3. Limit by depth if specified

	// Simplified implementation for now
	objectsToSend := []string{}

	// Add all wanted objects
	for _, want := range wants {
		// In a real implementation, we would walk the commit graph
		// and include all reachable objects not in the client's haves

		// For now, just include the want itself
		objectsToSend = append(objectsToSend, want)

		// Add some simulated objects
		objectsPath := filepath.Join(repoPath, ".vec", "objects")

		// Fetch objects from storage
		storage := objects.NewStorage(objectsPath)

		// Get objects reachable from this want
		reachable, err := storage.GetReachableObjects(want, depth)
		if err != nil {
			return nil, err
		}

		// Add reachable objects not in haves
		for _, obj := range reachable {
			if !contains(haves, obj) && !contains(objectsToSend, obj) {
				objectsToSend = append(objectsToSend, obj)
			}
		}
	}

	return objectsToSend, nil
}

// createPackfile creates a packfile containing the specified objects
func createPackfile(repoPath string, objectIDs []string) ([]byte, error) {
	// In a real implementation, this would use the proper packfile creation logic

	// Get object storage
	objectsPath := filepath.Join(repoPath, ".vec", "objects")
	storage := objects.NewStorage(objectsPath)

	// Create packfile
	creator := packfile.NewCreator()

	// Add objects to packfile
	for _, id := range objectIDs {
		obj, err := storage.GetObject(id)
		if err != nil {
			return nil, err
		}

		err = creator.AddObject(obj)
		if err != nil {
			return nil, err
		}
	}

	// Create packfile data
	var buf bytes.Buffer
	if err := creator.WriteTo(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// supportsSideBand checks if the client supports side-band encoding
func supportsSideBand(r *http.Request) bool {
	// In a real implementation, this would check if the client's initial "want" command
	// included the "side-band" or "side-band-64k" capability

	// For now, assume it's supported
	return true
}

// sendPackfileWithSideBand sends the packfile with side-band encoding
func sendPackfileWithSideBand(w http.ResponseWriter, packfileData []byte) {
	// Send acknowledgment
	WritePacketLine(w, []byte("NAK\n"))

	// Packfile data is sent on channel 1
	// Break the packfile into smaller chunks
	const chunkSize = 8192
	for i := 0; i < len(packfileData); i += chunkSize {
		end := i + chunkSize
		if end > len(packfileData) {
			end = len(packfileData)
		}

		// Prepend channel byte (1 = packfile data)
		chunk := append([]byte{1}, packfileData[i:end]...)
		WritePacketLine(w, chunk)

		// Occasionally send progress on channel 2
		if i%65536 == 0 && i > 0 {
			progress := fmt.Sprintf("Sending packfile: %d/%d bytes\n", i, len(packfileData))
			WritePacketLine(w, append([]byte{2}, []byte(progress)...))
		}
	}

	// Send flush packet
	WriteFlushPacket(w)
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
