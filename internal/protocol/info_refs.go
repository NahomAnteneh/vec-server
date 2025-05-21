package protocol

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// InfoRefsHandler handles the info/refs protocol endpoint
func InfoRefsHandler(repoManager *repository.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get repository path from request context
		owner := r.PathValue("owner")
		repoName := r.PathValue("repo")

		// Check if repository exists
		if !repoManager.RepositoryExists(owner, repoName) {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Get service parameter (upload-pack or receive-pack)
		service := r.URL.Query().Get("service")
		if service != "vec-upload-pack" && service != "vec-receive-pack" {
			http.Error(w, "Invalid service", http.StatusBadRequest)
			return
		}

		// Set content type
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))

		// Get repository path
		repoPath := repoManager.GetRepoPath(owner, repoName)

		// Read all refs from the repository
		refs, err := getRepositoryRefs(repoPath)
		if err != nil {
			http.Error(w, "Error reading refs", http.StatusInternalServerError)
			return
		}

		// Write service advertisement
		w.Write(formatServiceAnnouncement(service))

		// Write refs advertisement
		for _, ref := range refs {
			w.Write(formatRef(ref))
		}

		// End with a flush packet
		w.Write([]byte("0000"))
	}
}

// getRepositoryRefs reads all refs from a repository
func getRepositoryRefs(repoPath string) ([]string, error) {
	// This is a simplified implementation
	// In a real implementation, you would read all refs from the repository
	// and format them as "hash refname"

	// Example: read HEAD ref
	headPath := filepath.Join(repoPath, ".vec", "HEAD")
	headContent, err := os.ReadFile(headPath)
	if err != nil {
		return nil, err
	}

	// Parse HEAD ref
	headRef := strings.TrimSpace(string(headContent))
	if strings.HasPrefix(headRef, "ref: ") {
		// HEAD points to a ref
		refName := strings.TrimPrefix(headRef, "ref: ")
		refPath := filepath.Join(repoPath, ".vec", refName)
		refHash, err := os.ReadFile(refPath)
		if err != nil {
			// If the ref doesn't exist yet, use all zeros
			return []string{fmt.Sprintf("0000000000000000000000000000000000000000 %s", refName)}, nil
		}
		return []string{fmt.Sprintf("%s %s", strings.TrimSpace(string(refHash)), refName)}, nil
	}

	// HEAD is detached, use HEAD as the hash
	return []string{fmt.Sprintf("%s HEAD", strings.TrimSpace(headRef))}, nil
}

// formatServiceAnnouncement formats the service announcement packet
func formatServiceAnnouncement(service string) []byte {
	// Format: len+"# service="+service+"\n"+len+"\n"
	announcement := fmt.Sprintf("# service=%s\n", service)
	payloadSize := len(announcement) + 4 // +4 for the length prefix
	return []byte(fmt.Sprintf("%04x%s0000", payloadSize, announcement))
}

// formatRef formats a ref line for the protocol
func formatRef(ref string) []byte {
	// Format: len+line+"\n"
	line := ref + "\n"
	return []byte(fmt.Sprintf("%04x%s", len(line)+4, line))
}
