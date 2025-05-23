FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vec-repo-server ./cmd/server

# Use a small alpine image for the final container
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/vec-repo-server .

# Copy configuration
COPY --from=builder /app/config/repository-server.yml /root/config/repository-server.yml

# Copy documentation
COPY --from=builder /app/REPOSITORY_SERVER.md /root/REPOSITORY_SERVER.md
COPY --from=builder /app/README.md /root/README.md

# Create data directory for repositories
RUN mkdir -p /data/repositories

# Set environment variables
ENV VEC_SERVER_PORT=8080
ENV VEC_REPO_PATH=/data/repositories
ENV VEC_CONFIG_PATH=/root/config/repository-server.yml

# Expose the server port
EXPOSE 8080

# Create volume for persistent data
VOLUME ["/data/repositories"]

# Run the server
CMD ["./vec-repo-server"] 