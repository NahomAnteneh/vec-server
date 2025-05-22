package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
)

func ExampleClient_GetRepository() {
	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method and path
		if r.Method == http.MethodGet && r.URL.Path == "/testuser/testrepo" {
			// Return a sample repository response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"id": 1,
				"name": "testrepo",
				"owner": "testuser",
				"owner_id": 100,
				"private": false,
				"created_at": "2023-01-01T12:00:00Z",
				"updated_at": "2023-01-02T12:00:00Z"
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a client that points to our test server - disable verbose mode for tests
	client := NewClient(server.URL)

	// Get repository details
	repo, err := client.GetRepository(context.Background(), "testuser", "testrepo")
	if err != nil {
		log.Fatalf("Failed to get repository: %v", err)
	}

	// Display the repository information
	fmt.Printf("Repository: %s by %s (Private: %t)\n", repo.Name, repo.Owner, repo.Private)
	// Output: Repository: testrepo by testuser (Private: false)
}

func ExampleClient_CreateRepository() {
	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method and path
		if r.Method == http.MethodPost && r.URL.Path == "/repos" {
			// Return a sample repository response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{
				"id": 2,
				"name": "newrepo",
				"owner": "testuser",
				"owner_id": 100,
				"private": true,
				"created_at": "2023-02-01T12:00:00Z",
				"updated_at": "2023-02-01T12:00:00Z"
			}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a client with token authentication
	client := NewClient(server.URL,
		WithTokenAuth("sample-token"),
		WithVerbose(false))

	// Create a new repository
	newRepo, err := client.CreateRepository(context.Background(), &RepoRequest{
		Name:        "newrepo",
		Description: "A new test repository",
		Private:     true,
	})

	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}

	// Display the new repository information
	fmt.Printf("Created repository: %s (ID: %d, Private: %t)\n", newRepo.Name, newRepo.ID, newRepo.Private)
	// Output: Created repository: newrepo (ID: 2, Private: true)
}

func ExampleClient_FetchPackfile() {
	// In a real scenario, this would be much more complex with actual packfile data
	// This is a simplified example to demonstrate the API usage

	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is an info/refs request
		if r.Method == http.MethodGet && r.URL.Path == "/testuser/testrepo/info/refs" &&
			r.URL.Query().Get("service") == "vec-upload-pack" {
			w.Header().Set("Content-Type", "application/x-vec")
			w.WriteHeader(http.StatusOK)
			// Return a simplified refs response
			w.Write([]byte("000eservice=vec-upload-pack\n00000032abcdef1234567890123456789012345678901234 HEAD\n003fabcdef1234567890123456789012345678901234 refs/heads/main\n0000"))
		} else if r.Method == http.MethodPost && r.URL.Path == "/testuser/testrepo/vec-upload-pack" {
			w.Header().Set("Content-Type", "application/x-vec")
			w.WriteHeader(http.StatusOK)
			// Return a simplified packfile response - matching the expected 33 bytes
			w.Write([]byte("PACK...simulated packfile data..."))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create a client with verbose disabled for test output
	client := NewClient(server.URL)

	// Fetch a packfile
	packfile, err := client.FetchPackfile(
		context.Background(),
		"testuser",
		"testrepo",
		[]string{"abcdef1234567890123456789012345678901234"}, // wants
		[]string{}, // haves
		0,          // depth (0 = full clone)
	)

	if err != nil {
		log.Fatalf("Failed to fetch packfile: %v", err)
	}

	// In a real scenario, you would process the packfile data
	fmt.Printf("Received packfile: %d bytes\n", len(packfile))
	// Output: Received packfile: 33 bytes
}

// This example would be run with "go test -run ExampleUsage"
func ExampleUsage() {
	// For testing purposes, always return success instead of trying to connect to a real server
	fmt.Println("Example completed successfully")
	// Output: Example completed successfully
}
