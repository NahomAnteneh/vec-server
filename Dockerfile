FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vec-server ./cmd/server

# Use a small alpine image for the final container
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/vec-server .

# Create data directory for repositories
RUN mkdir -p /data/repos

# Set environment variables
ENV VEC_SERVER_PORT=8000
ENV VEC_REPO_PATH=/data/repos

# Expose the server port
EXPOSE 8000

# Run the server
CMD ["./vec-server"] 