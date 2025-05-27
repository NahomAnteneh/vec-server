package protocol

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath" // Import for joining paths for refs
	"strings"

	// For core.ReadHEADFile

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

		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		w.Header().Set("Cache-Control", "no-cache")

		if err := WritePacketLine(w, formatServiceAnnouncement(service)); err != nil {
			logger.Printf("INFO_REFS: Error writing service header: %v", err)
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}

		capabilities := getCapabilities(service)
		logger.Printf("INFO_REFS: Capabilities: %s", capabilities)
		firstRefWritten := false

		// 1. Get and write HEAD information
		headCommitHash, err := repoManager.GetHeadCommitHash(repoPath)
		if err != nil {
			logger.Printf("INFO_REFS: Error reading HEAD for %s: %v", repoPath, err)
		} else if headCommitHash != "" && headCommitHash != strings.Repeat("0", 64) {
			var headBuf bytes.Buffer
			headBuf.WriteString(fmt.Sprintf("%s HEAD", headCommitHash))
			headBuf.WriteByte(0x00) // NUL byte
			headBuf.WriteString(capabilities)

			logger.Printf("INFO_REFS: Writing HEAD ref: %s (commit: %s)", "HEAD", headCommitHash)
			if err := WritePacketLine(w, headBuf.Bytes()); err != nil {
				logger.Printf("INFO_REFS: Error writing HEAD ref line: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
			firstRefWritten = true
		}

		// 2. Get and write all branch refs (refs/heads/*)
		branchMap, err := repoManager.GetBranches(repoPath)
		if err != nil {
			logger.Printf("INFO_REFS: Error reading branches for %s: %v", repoPath, err)
			// If no branches, it could be an empty repo. If HEAD wasn't written, might not be an error to have no refs.
			if !firstRefWritten && strings.Contains(err.Error(), "not found") { // If it's a typical not found error and no HEAD, maybe it's an empty repo
				// Don't send error yet, just means no refs to list after HEAD
			} else {
				http.Error(w, "Error reading refs", http.StatusInternalServerError)
				return
			}
		}

		// Add a special check for empty ref files
		if len(branchMap) == 0 {
			// Manually check common branches in case refs aren't being properly read but exist as files
			repoCorePath := filepath.Join(repoPath, ".vec")
			commonBranches := []string{"main"}

			for _, branch := range commonBranches {
				branchPath := filepath.Join(repoCorePath, "refs", "heads", branch)
				if _, err := os.Stat(branchPath); err == nil {
					// Branch file exists, but might be empty
					branchContent, err := os.ReadFile(branchPath)
					if err == nil && len(branchContent) > 0 {
						commitHash := strings.TrimSpace(string(branchContent))
						if commitHash != "" && commitHash != strings.Repeat("0", 64) {
							logger.Printf("INFO_REFS: Found commit %s in branch file %s that wasn't returned by GetBranches", commitHash, branch)
							branchMap[branch] = commitHash
						}
					}
				}
			}
		}

		for branchName, commitHash := range branchMap {
			if commitHash == "" || commitHash == strings.Repeat("0", 64) { // Skip empty or null hashes
				logger.Printf("INFO_REFS: Skipping empty or zero hash for ref refs/heads/%s", branchName)
				continue
			}
			refFullName := filepath.Join("refs", "heads", branchName) // Git typically uses / for network paths
			refFullName = strings.ReplaceAll(refFullName, "\\", "/")  // Ensure forward slashes

			var refLineBytes []byte
			if !firstRefWritten { // If HEAD wasn't written (e.g. empty repo, no HEAD commit yet)
				var branchBuf bytes.Buffer
				branchBuf.WriteString(fmt.Sprintf("%s %s", commitHash, refFullName))
				branchBuf.WriteByte(0x00) // NUL byte
				branchBuf.WriteString(capabilities)
				refLineBytes = branchBuf.Bytes()
				firstRefWritten = true
			} else {
				refLineBytes = []byte(fmt.Sprintf("%s %s", commitHash, refFullName))
			}
			logger.Printf("INFO_REFS: Writing branch ref: %s -> %s", refFullName, commitHash)
			if err := WritePacketLine(w, refLineBytes); err != nil {
				logger.Printf("INFO_REFS: Error writing ref line: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
		}

		// If after all this, no refs were written (e.g., truly empty repo with no HEAD and no branches),
		// some clients might expect at least the # service line and a flush packet.
		// Git typically sends `0000` (flush) even if there are no refs other than the capabilities line with HEAD.
		// If `firstRefWritten` is false, it means no refs (including HEAD) had a valid commit hash.
		// In such a case (truly empty repo), Git server sends `hash_of_empty_commit refs/heads/master capabilities` (if master is default)
		// or just `0000` if no refs at all. Our current logic will send 0000 if no refs are written.

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
