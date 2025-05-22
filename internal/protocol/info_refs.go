package protocol

import (
	"fmt"
	"io/fs"
	"log"
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
		owner := r.PathValue("username")
		repoName := r.PathValue("repo")

		log.Printf("INFO_REFS: Request for owner=%s, repo=%s, URL=%s", owner, repoName, r.URL.String())

		// Check if repository exists
		repoExists := repoManager.RepositoryExists(owner, repoName)
		log.Printf("INFO_REFS: Repository exists check: %v", repoExists)
		if !repoExists {
			log.Printf("INFO_REFS: Repository not found: owner=%s, repo=%s", owner, repoName)
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Get service parameter (upload-pack or receive-pack)
		service := r.URL.Query().Get("service")
		log.Printf("INFO_REFS: Service requested: %s", service)
		if service != "vec-upload-pack" && service != "vec-receive-pack" {
			log.Printf("INFO_REFS: Invalid service: %s", service)
			http.Error(w, "Invalid service", http.StatusBadRequest)
			return
		}

		// Set content type
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		// Set cache control to no-cache to ensure fresh responses
		w.Header().Set("Cache-Control", "no-cache")

		// Get repository path
		repoPath := repoManager.GetRepoPath(owner, repoName)
		log.Printf("INFO_REFS: Repository path: %s", repoPath)

		// Read all refs from the repository
		refs, err := getRepositoryRefs(repoPath)
		if err != nil {
			log.Printf("INFO_REFS: Error reading refs: %v", err)
			http.Error(w, "Error reading refs", http.StatusInternalServerError)
			return
		}
		log.Printf("INFO_REFS: Found %d refs", len(refs))

		// Write service advertisement
		serviceHeader := formatServiceAnnouncement(service)
		if _, err := w.Write(serviceHeader); err != nil {
			log.Printf("INFO_REFS: Error writing service header: %v", err)
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}

		// Generate capabilities string based on service
		capabilities := getCapabilities(service)
		log.Printf("INFO_REFS: Capabilities: %s", capabilities)

		// Write refs with capabilities attached to the first ref
		firstRef := true
		for refName, hash := range refs {
			var refLine string
			if firstRef {
				// First ref includes capabilities
				refLine = fmt.Sprintf("%s %s\x00%s", hash, refName, capabilities)
				firstRef = false
			} else {
				refLine = fmt.Sprintf("%s %s", hash, refName)
			}

			log.Printf("INFO_REFS: Writing ref: %s -> %s", refName, hash)
			// Format and write the ref line
			if err := WritePacketLine(w, []byte(refLine)); err != nil {
				log.Printf("INFO_REFS: Error writing ref line: %v", err)
				http.Error(w, "Error writing response", http.StatusInternalServerError)
				return
			}
		}

		// End with a flush packet
		if err := WriteFlushPacket(w); err != nil {
			log.Printf("INFO_REFS: Error writing flush packet: %v", err)
			http.Error(w, "Error writing response", http.StatusInternalServerError)
			return
		}

		log.Printf("INFO_REFS: Successfully completed request for %s/%s", owner, repoName)
	}
}

// getRepositoryRefs reads all refs from a repository and returns a map of ref name to hash
func getRepositoryRefs(repoPath string) (map[string]string, error) {
	refs := make(map[string]string)

	// Get the HEAD reference
	headPath := filepath.Join(repoPath, ".vec", "HEAD")
	log.Printf("REFS: Reading HEAD from %s", headPath)
	headContent, err := os.ReadFile(headPath)
	if err == nil {
		headRef := strings.TrimSpace(string(headContent))
		log.Printf("REFS: HEAD content: %s", headRef)
		if strings.HasPrefix(headRef, "ref: ") {
			// Symbolic ref
			refTarget := strings.TrimPrefix(headRef, "ref: ")
			refs["HEAD"] = refTarget // Store the symbolic reference
			log.Printf("REFS: HEAD is symbolic ref to %s", refTarget)

			// Try to resolve the target ref
			targetPath := filepath.Join(repoPath, ".vec", refTarget)
			log.Printf("REFS: Trying to resolve target ref at %s", targetPath)
			targetContent, err := os.ReadFile(targetPath)
			if err == nil {
				hash := strings.TrimSpace(string(targetContent))
				log.Printf("REFS: Target ref resolved to hash: %s", hash)
				// Check if it's the all-zeros hash (empty repository)
				if hash == "0000000000000000000000000000000000000000000000000000000000000000" {
					log.Printf("REFS: Found all-zeros hash, treating as empty repository")
					// For empty repositories, don't include the reference
					// This will prevent the client from reporting "resource not found"
					// and will just clone an empty repository
					return refs, nil
				}
				refs[refTarget] = hash
			} else if os.IsNotExist(err) {
				log.Printf("REFS: Target ref doesn't exist yet, treating as empty repository")
				// If the ref doesn't exist yet, don't include it in the refs
				// rather than using all zeros
				return refs, nil
			} else {
				log.Printf("REFS: Error reading target ref: %v", err)
				return nil, fmt.Errorf("error reading ref %s: %w", refTarget, err)
			}
		} else {
			// Detached HEAD
			log.Printf("REFS: HEAD is detached, hash: %s", headRef)
			refs["HEAD"] = strings.TrimSpace(string(headContent))
		}
	} else {
		log.Printf("REFS: Error reading HEAD: %v", err)
	}

	// Walk through the refs directory
	refsDir := filepath.Join(repoPath, ".vec", "refs")
	log.Printf("REFS: Walking refs directory: %s", refsDir)
	err = filepath.WalkDir(refsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("REFS: Error walking path %s: %v", path, err)
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		log.Printf("REFS: Found ref file: %s", path)
		// Read the ref content
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("REFS: Error reading ref file %s: %v", path, err)
			return fmt.Errorf("error reading ref file %s: %w", path, err)
		}

		// Extract the ref name relative to the refs directory
		relPath, err := filepath.Rel(refsDir, path)
		if err != nil {
			log.Printf("REFS: Error getting relative path for %s: %v", path, err)
			return fmt.Errorf("error getting relative path: %w", err)
		}

		// Use "/" as separator for ref names
		refName := "refs/" + strings.ReplaceAll(relPath, string(os.PathSeparator), "/")
		hash := strings.TrimSpace(string(content))
		log.Printf("REFS: Adding ref %s with hash %s", refName, hash)

		// Only include non-empty hashes (not all zeros)
		if hash != "0000000000000000000000000000000000000000000000000000000000000000" {
			refs[refName] = hash
		} else {
			log.Printf("REFS: Skipping all-zeros hash for ref %s", refName)
		}

		return nil
	})

	// If refs directory doesn't exist yet, it's not an error (new repo)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("REFS: Error walking refs directory: %v", err)
		return nil, fmt.Errorf("error walking refs directory: %w", err)
	} else if os.IsNotExist(err) {
		log.Printf("REFS: Refs directory doesn't exist yet (new repo)")
	}

	log.Printf("REFS: Returning %d refs", len(refs))
	return refs, nil
}

// formatServiceAnnouncement formats the service announcement packet
func formatServiceAnnouncement(service string) []byte {
	// Format: "# service=vec-upload-pack\n" or "# service=vec-receive-pack\n"
	announcement := fmt.Sprintf("# service=%s\n", service)

	// Encode as packet line
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("%04x%s", len(announcement)+4, announcement))
	buf.WriteString("0000") // Flush packet

	return []byte(buf.String())
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

// formatRef formats a ref line for the protocol with capabilities for the first ref
func formatRef(refLine string) []byte {
	// Add newline if not present
	if !strings.HasSuffix(refLine, "\n") {
		refLine += "\n"
	}

	// Format with length prefix
	return []byte(fmt.Sprintf("%04x%s", len(refLine)+4, refLine))
}
