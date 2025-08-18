FROM golang:1.23.3-alpine AS builder

RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o verifier-server \
    ./cmd/server

FROM alpine:latest

# Install Python and required packages
RUN apk add --no-cache \
    ca-certificates \
    python3 \
    py3-requests \
    wget \
    && rm -rf /var/cache/apk/*

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the Go binary
COPY --from=builder /app/verifier-server .

# Copy the scripts folder
COPY scripts/ .

# Set proper permissions (AFTER copying scripts)
RUN chown -R appuser:appgroup /app && \
    chmod +x start.sh

# Switch to non-root user
USER appuser

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/v1/ping || exit 1

# Run the start script
ENTRYPOINT ["./start.sh"]