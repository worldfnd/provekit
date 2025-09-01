# Multi-stage Dockerfile for ProveKit Verifier Server
# Builds both the Go verifier binary and Rust verifier server

# Stage 1: Build Go verifier binary
FROM golang:1.23.3-alpine AS go-builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

WORKDIR /go-app

# Copy Go module files
COPY recursive-verifier/go.mod recursive-verifier/go.sum ./

# Download Go dependencies
RUN go mod download

# Copy Go source code
COPY recursive-verifier/ ./

# Build the Go verifier binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o verifier \
    ./cmd/cli

# Stage 2: Build Rust verifier server
FROM rust:1.85-alpine AS rust-builder

RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    git

WORKDIR /rust-app

# Copy workspace files for dependency resolution
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./

# Copy all workspace member directories (needed for workspace dependency resolution)
COPY provekit/ ./provekit/
COPY skyscraper/ ./skyscraper/
COPY tooling/ ./tooling/

# Build the verifier server in release mode
RUN cargo build --release --bin verifier-server

# Stage 3: Runtime image
FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    python3 \
    py3-requests \
    wget \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy the Go verifier binary from go-builder stage
COPY --from=go-builder /go-app/verifier ./verifier

# Copy the Rust verifier server binary from rust-builder stage
COPY --from=rust-builder /rust-app/target/release/verifier-server ./verifier-server

# Create necessary directories
RUN mkdir -p /app/artifacts /app/keys

# Set proper permissions
RUN chmod +x verifier verifier-server

# Create a non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Change ownership of the app directory
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the server port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Start the Rust verifier server
CMD ["./verifier-server"]
