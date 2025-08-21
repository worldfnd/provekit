FROM golang:1.23.3-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o verifier-server \
    ./cmd/server

FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    python3 \
    py3-requests \
    wget \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder /app/verifier-server .

COPY scripts/ .

# Set proper permissions (AFTER copying scripts and binary)
RUN mkdir -p /app/keys && \
    chmod +x start.sh && \
    chmod +x verifier-server

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/v1/ping || exit 1

# Run the start script
CMD ["./start.sh"]