package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
)

// TestClient demonstrates the usage of the Vec client with a mock server
func TestClient() {
	// Create a mock server that simulates the Vec server API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log incoming request
		fmt.Printf("Request: %s %s\n", r.Method, r.URL.Path)

		// Handle different API endpoints
		switch {
		// List repositories
		case r.Method == http.MethodGet && r.URL.Path == "/repos":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"repositories": [
					{
						"id": 1,
						"name": "repo1",
						"owner": "testuser",
						"owner_id": 100,
						"private": false,
						"created_at": "2023-01-01T12:00:00Z",
						"updated_at": "2023-01-02T12:00:00Z"
					},
					{
						"id": 2,
						"name": "repo2",
						"owner": "testuser",
						"owner_id": 100,
						"private": true,
						"created_at": "2023-02-01T12:00:00Z",
						"updated_at": "2023-02-02T12:00:00Z"
					}
				]
			}`))

		// Get repository details
		case r.Method == http.MethodGet && r.URL.Path == "/testuser/testrepo":
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

		// Create repository
		case r.Method == http.MethodPost && r.URL.Path == "/repos":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{
				"id": 3,
				"name": "newrepo",
				"owner": "testuser",
				"owner_id": 100,
				"private": true,
				"created_at": "2023-03-01T12:00:00Z",
				"updated_at": "2023-03-01T12:00:00Z"
			}`))

		// Get references
		case r.Method == http.MethodGet && r.URL.Path == "/testuser/testrepo/info/refs":
			w.Header().Set("Content-Type", "application/x-vec")
			w.WriteHeader(http.StatusOK)
			// Simplified response format for info/refs with service parameter
			w.Write([]byte("000eservice=vec-upload-pack\n00000032abcdef1234567890123456789012345678901234 HEAD\n003fabcdef1234567890123456789012345678901234 refs/heads/main\n0000"))

		// Upload pack (fetch operation)
		case r.Method == http.MethodPost && r.URL.Path == "/testuser/testrepo/vec-upload-pack":
			w.Header().Set("Content-Type", "application/x-vec")
			w.WriteHeader(http.StatusOK)
			// Simplified packfile response
			w.Write([]byte("PACK...simulated packfile data..."))

		// Default: not found
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Not found"}`))
		}
	}))
	defer server.Close()

	// Create a client with our test server URL
	client := NewClient(server.URL, WithTokenAuth("test-token"), WithVerbose(true), WithLogger(func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}))

	ctx := context.Background()

	// TEST 1: List repositories
	fmt.Println("\n=== TEST 1: List Repositories ===")
	repos, err := client.ListRepositories(ctx)
	if err != nil {
		log.Fatalf("Failed to list repositories: %v", err)
	}

	fmt.Printf("Found %d repositories:\n", len(repos))
	for _, repo := range repos {
		fmt.Printf("- %s (owner: %s, private: %t)\n", repo.Name, repo.Owner, repo.Private)
	}

	// TEST 2: Get repository details
	fmt.Println("\n=== TEST 2: Get Repository ===")
	repo, err := client.GetRepository(ctx, "testuser", "testrepo")
	if err != nil {
		log.Fatalf("Failed to get repository: %v", err)
	}

	fmt.Printf("Repository: %s by %s (ID: %d, Private: %t)\n",
		repo.Name, repo.Owner, repo.ID, repo.Private)

	// TEST 3: Create repository
	fmt.Println("\n=== TEST 3: Create Repository ===")
	newRepo, err := client.CreateRepository(ctx, &RepoRequest{
		Name:        "newrepo",
		Description: "A test repository",
		Private:     true,
	})

	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}

	fmt.Printf("Created repository: %s (ID: %d, Owner: %s, Private: %t)\n",
		newRepo.Name, newRepo.ID, newRepo.Owner, newRepo.Private)

	// TEST 4: Fetch packfile
	fmt.Println("\n=== TEST 4: Fetch Packfile ===")
	packfile, err := client.FetchPackfile(
		ctx,
		"testuser",
		"testrepo",
		[]string{"abcdef1234567890123456789012345678901234"}, // wants
		[]string{}, // haves
		0,          // depth (0 = full clone)
	)

	if err != nil {
		log.Fatalf("Failed to fetch packfile: %v", err)
	}

	fmt.Printf("Received packfile: %d bytes\n", len(packfile))

	// TEST 5: Error handling
	fmt.Println("\n=== TEST 5: Error Handling ===")
	_, err = client.GetRepository(ctx, "nonexistent", "repo")

	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	} else {
		log.Fatal("Expected error but got none")
	}
}

// Main function to run the test
func RunTest() {
	fmt.Println("Testing Vec Client...")
	TestClient()
	fmt.Println("\nAll tests completed successfully!")
}
