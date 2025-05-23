package protocol

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/NahomAnteneh/vec-server/internal/db/models"
	"github.com/NahomAnteneh/vec-server/internal/repository"
)

// InfoRefsHandler handles the info/refs protocol endpoint
func InfoRefsHandler(repoManager *repository.Manager, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner := r.PathValue("username")
		repoName := r.PathValue("repo")
		logger.Printf("INFO_REFS: Request for owner=%s, repo=%s, URL=%s", owner, repoName, r.URL.String())

		exists, err := repoManager.RepositoryExists(owner, repoName)
		if err != nil {
			logger.Printf("INFO_REFS: Error checking repository: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if !exists {
			logger.Printf("INFO_REFS: Repository not found: owner=%s, repo=%s", owner, repoName)
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		service := r.URL.Query().Get("service")
		if service != "vec-upload-pack" && service != "vec-receive-pack" {
			logger.Printf("INFO_REFS: Invalid service: %s", service)
			http.Error(w, "Invalid service", http.StatusBadRequest)
			return
		}

		repoPath, err := repoManager.GetRepoPath(owner, repoName)
		if err != nil {
			logger.Printf("INFO_REFS: Invalid repo path: %v", err)
			http.Error(w, "Invalid repository path", http.StatusBadRequest)
			return
		}

		repo := &models.Repository{Path: repoPath}
		refs, err := repoManager.GetRefs(repo)
		if err != nil {
			logger.Printf("INFO_REFS: Error reading refs for %s: %v", repoPath, err)
			http.Error(w, "Error reading refs", http.StatusInternalServerError)
			return
		}
		logger.Printf("INFO_REFS: Found %d refs", len(refs))

		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		w.Header().Set("Cache-Control", "no-cache")

		if err := WritePacketLine(w, formatServiceAnnouncement(service)); err != nil {
			logger.Printf("INFO_REFS: Error writing service header: %v", err)
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}

		capabilities := getCapabilities(service)
		logger.Printf("INFO_REFS: Capabilities: %s", capabilities)

		firstRef := true
		for refName, hash := range refs {
			if hash == strings.Repeat("0", 64) {
				logger.Printf("INFO_REFS: Skipping all-zeros hash for ref %s", refName)
				continue
			}
			var refLine string
			if firstRef {
				refLine = fmt.Sprintf("%s %s\x00%s", hash, refName, capabilities)
				firstRef = false
			} else {
				refLine = fmt.Sprintf("%s %s", hash, refName)
			}
			logger.Printf("INFO_REFS: Writing ref: %s -> %s", refName, hash)
			if err := WritePacketLine(w, []byte(refLine)); err != nil {
				logger.Printf("INFO_REFS: Error writing ref line: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
		}

		if err := WriteFlushPacket(w); err != nil {
			logger.Printf("INFO_REFS: Error writing flush packet: %v", err)
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}

		logger.Printf("INFO_REFS: Completed request for %s/%s", owner, repoName)
	}
}

// formatServiceAnnouncement formats the service announcement packet
func formatServiceAnnouncement(service string) []byte {
	announcement := fmt.Sprintf("# service=%s\n", service)
	return []byte(fmt.Sprintf("%04x%s", len(announcement)+4, announcement))
}

// getCapabilities returns the capabilities string based on the service type
func getCapabilities(service string) string {
	switch service {
	case "vec-upload-pack":
		return "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not agent=vec-server/1.0"
	case "vec-receive-pack":
		return "report-status delete-refs side-band-64k quiet atomic ofs-delta agent=vec-server/1.0"
	default:
		return ""
	}
}
