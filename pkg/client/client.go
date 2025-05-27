package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// Common constants
const (
	// Default timeout for HTTP requests
	DefaultTimeout = 60 * time.Second

	// Standard content types
	ContentTypeJSON = "application/json"
	ContentTypeVec  = "application/x-vec"

	// Service names for Vec Smart HTTP Protocol
	ServiceUploadPack  = "vec-upload-pack"
	ServiceReceivePack = "vec-receive-pack"
)

// Common error types
var (
	ErrNetworkError        = errors.New("network error occurred")
	ErrNotFound            = errors.New("resource not found")
	ErrAuthenticationError = errors.New("authentication failed")
	ErrPermissionDenied    = errors.New("permission denied")
	ErrBadRequest          = errors.New("bad request")
	ErrServerError         = errors.New("server error")
)

// Auth handles authentication for HTTP requests
type Auth interface {
	ApplyAuth(req *http.Request) error
}

// BasicAuth implements basic username/password authentication
type BasicAuth struct {
	Username string
	Password string
}

// ApplyAuth applies basic authentication to the request
func (a *BasicAuth) ApplyAuth(req *http.Request) error {
	req.SetBasicAuth(a.Username, a.Password)
	return nil
}

// TokenAuth implements token-based authentication
type TokenAuth struct {
	Token string
}

// ApplyAuth applies token authentication to the request
func (a *TokenAuth) ApplyAuth(req *http.Request) error {
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	return nil
}

// Repository represents a Vec repository
type Repository struct {
	ID        uint      `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	OwnerID   uint      `json:"owner_id"`
	Private   bool      `json:"private"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RepoRequest represents the data needed to create or update a repository
type RepoRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Private     bool   `json:"private"`
}

// Client represents the Vec client for interacting with a Vec server
type Client struct {
	httpClient    *http.Client
	baseURL       string
	auth          Auth
	verbose       bool
	requestLogger func(string, ...interface{})
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// WithTimeout sets the timeout for HTTP requests
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithBasicAuth sets basic authentication
func WithBasicAuth(username, password string) ClientOption {
	return func(c *Client) {
		c.auth = &BasicAuth{
			Username: username,
			Password: password,
		}
	}
}

// WithTokenAuth sets token-based authentication
func WithTokenAuth(token string) ClientOption {
	return func(c *Client) {
		c.auth = &TokenAuth{
			Token: token,
		}
	}
}

// WithVerbose enables or disables verbose output
func WithVerbose(verbose bool) ClientOption {
	return func(c *Client) {
		c.verbose = verbose
	}
}

// WithLogger sets a custom logger function
func WithLogger(logger func(string, ...interface{})) ClientOption {
	return func(c *Client) {
		c.requestLogger = logger
	}
}

// NewClient creates a new Vec client
func NewClient(baseURL string, options ...ClientOption) *Client {
	// Ensure baseURL ends with a slash
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: baseURL,
		verbose: false,
		requestLogger: func(format string, args ...interface{}) {
			// Default is to do nothing
		},
	}

	// Apply options
	for _, option := range options {
		option(client)
	}

	return client
}

// SetAuth sets the authentication method
func (c *Client) SetAuth(auth Auth) {
	c.auth = auth
}

// SetTimeout sets the timeout for HTTP requests
func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// SetVerbose enables or disables verbose output
func (c *Client) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// logRequest logs a request if verbose mode is enabled
func (c *Client) logRequest(format string, args ...interface{}) {
	if c.verbose {
		c.requestLogger(format, args...)
	}
}

// buildURL builds a full URL from the path
func (c *Client) buildURL(urlPath string) string {
	return c.baseURL + strings.TrimPrefix(urlPath, "/")
}

// Do performs an HTTP request and returns the response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Apply authentication if available
	if c.auth != nil {
		if err := c.auth.ApplyAuth(req); err != nil {
			return nil, fmt.Errorf("authentication error: %w", err)
		}
	}

	// Add standard headers
	req.Header.Set("User-Agent", "Vec-Client/1.0")

	// Log the request
	if c.verbose {
		c.logRequest("Request: %s %s", req.Method, req.URL.String())
	}

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()

		// Try to read error message
		body, _ := io.ReadAll(resp.Body)
		errMsg := string(body)

		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: %s", ErrNotFound, errMsg)
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", ErrAuthenticationError, errMsg)
		case http.StatusForbidden:
			return nil, fmt.Errorf("%w: %s", ErrPermissionDenied, errMsg)
		case http.StatusBadRequest:
			return nil, fmt.Errorf("%w: %s", ErrBadRequest, errMsg)
		default:
			return nil, fmt.Errorf("%w: %s (status code: %d)", ErrServerError, errMsg, resp.StatusCode)
		}
	}

	return resp, nil
}

// Get performs a GET request and returns the response body
func (c *Client) Get(ctx context.Context, urlPath string) ([]byte, error) {
	url := c.buildURL(urlPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// Post performs a POST request with JSON data and returns the response body
func (c *Client) Post(ctx context.Context, urlPath string, data interface{}) ([]byte, error) {
	url := c.buildURL(urlPath)

	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
		body = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeJSON)
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// Put performs a PUT request with JSON data and returns the response body
func (c *Client) Put(ctx context.Context, urlPath string, data interface{}) ([]byte, error) {
	url := c.buildURL(urlPath)

	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
		body = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeJSON)
	req.Header.Set("Accept", ContentTypeJSON)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// Delete performs a DELETE request and returns the response body
func (c *Client) Delete(ctx context.Context, urlPath string) error {
	url := c.buildURL(urlPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// PostBinary posts binary data and returns the response body
func (c *Client) PostBinary(ctx context.Context, urlPath string, data []byte, contentType string) ([]byte, error) {
	url := c.buildURL(urlPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if contentType == "" {
		contentType = ContentTypeVec
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", contentType)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// GetInfoRefs retrieves references using Vec Smart HTTP Protocol
func (c *Client) GetInfoRefs(ctx context.Context, username, repoName, service string) ([]byte, error) {
	url := c.buildURL(path.Join(username, repoName, "info/refs"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add service query parameter
	q := req.URL.Query()
	q.Add("service", service)
	req.URL.RawQuery = q.Encode()

	// Accept git content type
	req.Header.Set("Accept", ContentTypeVec)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// PostUploadPack sends a vec-upload-pack request for fetch/clone operations
func (c *Client) PostUploadPack(ctx context.Context, username, repoName string, data []byte) ([]byte, error) {
	url := c.buildURL(path.Join(username, repoName, ServiceUploadPack))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeVec)
	req.Header.Set("Accept", ContentTypeVec)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// PostReceivePack sends a vec-receive-pack request for push operations
func (c *Client) PostReceivePack(ctx context.Context, username, repoName string, data []byte) ([]byte, error) {
	url := c.buildURL(path.Join(username, repoName, ServiceReceivePack))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeVec)
	req.Header.Set("Accept", ContentTypeVec)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// ListRepositories lists all repositories accessible to the authenticated user
func (c *Client) ListRepositories(ctx context.Context) ([]Repository, error) {
	data, err := c.Get(ctx, "repos")
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	var resp struct {
		Repositories []Repository `json:"repositories"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Repositories, nil
}

// GetRepository retrieves details about a repository
func (c *Client) GetRepository(ctx context.Context, username, repoName string) (*Repository, error) {
	data, err := c.Get(ctx, path.Join(username, repoName))
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	var repo Repository
	if err := json.Unmarshal(data, &repo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &repo, nil
}

// CreateRepository creates a new repository for the authenticated user
func (c *Client) CreateRepository(ctx context.Context, request *RepoRequest) (*Repository, error) {
	data, err := c.Post(ctx, "repos", request)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	var repo Repository
	if err := json.Unmarshal(data, &repo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &repo, nil
}

// UpdateRepository updates an existing repository
func (c *Client) UpdateRepository(ctx context.Context, username, repoName string, request *RepoRequest) (*Repository, error) {
	data, err := c.Put(ctx, path.Join(username, repoName), request)
	if err != nil {
		return nil, fmt.Errorf("failed to update repository: %w", err)
	}

	var repo Repository
	if err := json.Unmarshal(data, &repo); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &repo, nil
}

// DeleteRepository deletes a repository
func (c *Client) DeleteRepository(ctx context.Context, username, repoName string) error {
	return c.Delete(ctx, path.Join(username, repoName))
}

// FetchPackfile fetches a packfile from the server using Vec Smart HTTP Protocol
func (c *Client) FetchPackfile(ctx context.Context, username, repoName string, wants []string, haves []string, depth int) ([]byte, error) {
	// Create the upload-pack request using packet lines
	var buf bytes.Buffer

	// Add want lines
	for i, want := range wants {
		var line string
		if i == 0 {
			// First want includes capabilities
			line = fmt.Sprintf("want %s multi_ack thin-pack side-band side-band-64k ofs-delta agent=vec/1.0\n", want)
		} else {
			line = fmt.Sprintf("want %s\n", want)
		}

		writePacketLine(&buf, []byte(line))
	}

	// Add depth limit if specified
	if depth > 0 {
		line := fmt.Sprintf("deepen %d\n", depth)
		writePacketLine(&buf, []byte(line))
	}

	// Send flush packet after wants
	writeFlushPacket(&buf)

	// Add have lines if present
	for _, have := range haves {
		line := fmt.Sprintf("have %s\n", have)
		writePacketLine(&buf, []byte(line))
	}

	// Send "done" to finish negotiation
	writePacketLine(&buf, []byte("done\n"))

	// Post the request
	return c.PostUploadPack(ctx, username, repoName, buf.Bytes())
}

// PushPackfile pushes a packfile to the server using Vec Smart HTTP Protocol
func (c *Client) PushPackfile(ctx context.Context, username, repoName string, refUpdates map[string]RefUpdate, packfile []byte) ([]byte, error) {
	// Create the receive-pack request using packet lines
	var buf bytes.Buffer

	// First line includes capabilities
	firstLine := true

	// Add ref updates
	for refName, update := range refUpdates {
		var line string
		if firstLine {
			// First ref update includes capabilities
			line = fmt.Sprintf("%s %s %s report-status side-band-64k agent=vec/1.0\n",
				update.OldHash, update.NewHash, refName)
			firstLine = false
		} else {
			line = fmt.Sprintf("%s %s %s\n", update.OldHash, update.NewHash, refName)
		}

		writePacketLine(&buf, []byte(line))
	}

	// Send flush packet to end ref updates
	writeFlushPacket(&buf)

	// Append packfile data (if any)
	if len(packfile) > 0 {
		buf.Write(packfile)
	}

	// Post the request
	return c.PostReceivePack(ctx, username, repoName, buf.Bytes())
}

// RefUpdate represents an update to a reference
type RefUpdate struct {
	OldHash string
	NewHash string
}

// Helper functions for packet line encoding

// writePacketLine writes a pkt-line to the buffer
func writePacketLine(w *bytes.Buffer, data []byte) error {
	// Length including 4-byte header plus data (plus newline if not present)
	length := len(data) + 4

	// Write the length header
	header := fmt.Sprintf("%04x", length)
	if _, err := w.WriteString(header); err != nil {
		return err
	}

	// Write the data
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

// writeFlushPacket writes a flush packet (0000) to the buffer
func writeFlushPacket(w *bytes.Buffer) error {
	_, err := w.WriteString("0000")
	return err
}
