.PHONY: build run clean test migrate dev

# Default target
all: build

# Build the server
build:
	go build -o vec-server ./cmd/server

# Run the server
run: build
	./vec-server

# Clean build artifacts
clean:
	rm -f vec-server

# Run tests
test:
	go test -v ./...

# Install dependencies
deps:
	go mod download

# Run database migrations
migrate:
	migrate -path internal/db/migrations -database "$(DATABASE_URL)" up

# Create a new migration
migrate-create:
	migrate create -ext sql -dir internal/db/migrations -seq $(name)

# Run with hot reload (requires air: go install github.com/cosmtrek/air@latest)
dev:
	air 