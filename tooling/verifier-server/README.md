# ProveKit Verifier Server

A containerized verifier server that combines a Rust HTTP server with a Go-based verifier binary for processing WHIR-based proof verification requests.

## Architecture

The verifier server consists of two main components:

1. **Rust HTTP Server** (`verifier-server`): Handles HTTP requests, downloads artifacts, and orchestrates verification
2. **Go Verifier Binary** (`verifier`): Performs the actual WHIR proof verification using gnark

## Building

### Prerequisites

- Docker and Docker Compose
- Alternatively: Rust 1.85+ and Go 1.23.3+ for local development

### Using Docker (Recommended)

#### Option 1: Using the build script
```bash
cd tooling/verifier-server
./build.sh
```

#### Option 2: Using docker-compose
```bash
cd tooling/verifier-server
docker-compose up --build
```

#### Option 3: Manual Docker build
```bash
# From the project root
docker build -f tooling/verifier-server/Dockerfile -t provekit-verifier-server .
```

### Local Development

#### Build Rust server
```bash
cargo build --release --bin verifier-server
```

#### Build Go verifier binary
```bash
cd recursive-verifier
go build -o verifier ./cmd/cli
```

## Running

### Using Docker Compose (Recommended)
```bash
cd tooling/verifier-server
docker-compose up
```

The server will be available at `http://localhost:3000`

### Using Docker directly
```bash
docker run -p 3000:3000 provekit-verifier-server:latest
```

### Local Development
```bash
# Make sure the Go verifier binary is available in the PATH or same directory
./target/release/verifier-server
```

## API Endpoints

### Health Check
```bash
GET /health
```

Returns server status and version information.

### Proof Verification
```bash
POST /verify
```

Verifies a Noir proof using the WHIR verification system.

**Request Body:**
```json
{
  "nps_url": "https://example.com/scheme.nps",
  "r1cs_url": "https://example.com/r1cs.json", 
  "pk_url": "https://example.com/proving_key.bin",
  "vk_url": "https://example.com/verification_key.bin",
  "noir_proof": "<base64-encoded-proof>",
  "verification_params": {
    "max_verification_time": 300
  },
  "metadata": {
    "request_id": "unique-request-id"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "verification_time_ms": 1500,
  "request_id": "unique-request-id",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Configuration

The server can be configured using environment variables:

- `RUST_LOG`: Log level (default: `info`)
- `RUST_BACKTRACE`: Enable backtraces (default: `1`)

## File Structure

```
tooling/verifier-server/
├── src/
│   ├── main.rs           # Server entry point
│   ├── handlers.rs       # HTTP request handlers
│   ├── models.rs         # Data models
│   └── error.rs          # Error handling
├── Dockerfile            # Multi-stage Docker build
├── docker-compose.yml    # Docker Compose configuration
├── build.sh             # Build script
├── README.md            # This file
└── Cargo.toml           # Rust dependencies
```

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port mapping in docker-compose.yml or use `-p 3001:3000` instead
2. **Build failures**: Ensure Docker has enough memory allocated (at least 4GB recommended)
3. **Go binary not found**: The Docker build automatically includes the Go verifier binary

### Logs

To view logs:
```bash
docker-compose logs -f verifier-server
```

### Health Check

The container includes a health check that pings `/health` every 30 seconds. Check container health:
```bash
docker ps
```

Look for the "STATUS" column to see health status.

## Development

### Local Testing

1. Build both components locally
2. Ensure the Go `verifier` binary is in your PATH or the same directory as the Rust server
3. Run the Rust server: `cargo run --bin verifier-server`

### Debugging

Enable debug logging:
```bash
RUST_LOG=debug cargo run --bin verifier-server
```

Or in Docker:
```yaml
environment:
  - RUST_LOG=debug
```
