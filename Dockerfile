# Dockerfile

# --- Stage 1: Build the binary ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files and download them to a separate layer for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application, creating a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-service .

# --- Stage 2: Create the final, minimal image ---
FROM alpine:latest

WORKDIR /root/

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/auth-service .

# Expose the port the application will run on
EXPOSE 8080

# Run the application
CMD ["./auth-service"]