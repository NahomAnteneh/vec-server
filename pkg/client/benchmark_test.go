package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkClient_GetRepository benchmarks the GetRepository method
func BenchmarkClient_GetRepository(b *testing.B) {
	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer server.Close()

	// Create a client
	client := NewClient(server.URL)
	ctx := context.Background()

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.GetRepository(ctx, "testuser", "testrepo")
		if err != nil {
			b.Fatalf("Failed to get repository: %v", err)
		}
	}
}

// BenchmarkClient_CreateRepository benchmarks the CreateRepository method
func BenchmarkClient_CreateRepository(b *testing.B) {
	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a sample repository response
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
	}))
	defer server.Close()

	// Create a client
	client := NewClient(server.URL)
	ctx := context.Background()

	// Create repo request
	repoRequest := &RepoRequest{
		Name:        "newrepo",
		Description: "A test repository",
		Private:     true,
	}

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.CreateRepository(ctx, repoRequest)
		if err != nil {
			b.Fatalf("Failed to create repository: %v", err)
		}
	}
}

// BenchmarkClient_FetchPackfile benchmarks the FetchPackfile method
func BenchmarkClient_FetchPackfile(b *testing.B) {
	// Create a test server that simulates a Vec server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/testuser/testrepo/vec-upload-pack" {
			w.Header().Set("Content-Type", "application/x-vec")
			w.WriteHeader(http.StatusOK)
			// Generate a 1KB packfile to test performance
			packfileData := make([]byte, 1024)
			for i := range packfileData {
				packfileData[i] = byte(i % 256)
			}
			w.Write(packfileData)
		}
	}))
	defer server.Close()

	// Create a client
	client := NewClient(server.URL)
	ctx := context.Background()

	wants := []string{"abcdef1234567890123456789012345678901234"}

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.FetchPackfile(ctx, "testuser", "testrepo", wants, nil, 0)
		if err != nil {
			b.Fatalf("Failed to fetch packfile: %v", err)
		}
	}
}

// BenchmarkClient_ErrorHandling benchmarks the error handling performance
func BenchmarkClient_ErrorHandling(b *testing.B) {
	// Create a test server that always returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer server.Close()

	// Create a client
	client := NewClient(server.URL)
	ctx := context.Background()

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.GetRepository(ctx, "nonexistent", "repo")
		if err == nil {
			b.Fatal("Expected error but got none")
		}
	}
}
