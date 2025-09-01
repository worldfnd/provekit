# ProveKit Verifier Server

<<<<<<< HEAD
HTTP server combining Rust (API) + Go (verifier binary) for WHIR-based proof verification.

## Quick Start

=======
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
>>>>>>> 8764374 (feat: add verifier server)
```bash
cd tooling/verifier-server
docker-compose up --build
```

<<<<<<< HEAD
Server runs at `http://localhost:3000`

## API

### Health Check
```bash
curl http://localhost:3000/health
```

### Verify Proof
```bash
curl -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "pkvUrl": "https://example.com/verifier.pkv",
    "r1csUrl": "https://example.com/r1cs.json", 
    "pkUrl": "https://example.com/proving_key.bin", (optional)
    "vkUrl": "https://example.com/verification_key.bin", (optional)
    "np": { /* NoirProof JSON */ },
  }'
=======
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
>>>>>>> 8764374 (feat: add verifier server)
```

**Response:**
```json
{
<<<<<<< HEAD
  "isValid": true,
  "result": {
    "status": "valid",
    "verificationTimeMs": 1500
  },
  "metadata": {
    "serverVersion": "0.1.0",
    "requestId": "unique-request-id"
  }
}
```

## Build Options

```bash
# Docker (recommended)
./build.sh
docker-compose up --build

# Local development
cargo run --bin verifier-server
```

## Environment Variables

### Server Configuration
- `VERIFIER_HOST` - Server host (default: `0.0.0.0`)
- `VERIFIER_PORT` - Server port (default: `3000`)
- `VERIFIER_MAX_REQUEST_SIZE` - Maximum request body size in bytes (default: `10485760` = 10MB)
- `VERIFIER_REQUEST_TIMEOUT` - Request timeout in seconds (default: `1200` = 20 minutes)
- `VERIFIER_SEMAPHORE_LIMIT` - Max concurrent verifications (default: `1`)

### Verification Configuration
- `VERIFIER_BINARY_PATH` - Go verifier binary path (default: `./verifier`)
- `VERIFIER_DEFAULT_MAX_TIME` - Default max verification time in seconds (default: `300` = 5 minutes)
- `VERIFIER_TIMEOUT_SECONDS` - Verifier binary timeout in seconds (default: `1200` = 20 minutes)

### Artifact Configuration
- `VERIFIER_ARTIFACTS_DIR` - Artifact cache directory (default: `./artifacts`)

### Logging
- `RUST_LOG` - Log level (default: `info`)

## Architecture

- **Rust HTTP Server**: Handles requests, downloads artifacts, orchestrates verification
- **Go Verifier Binary**: Performs WHIR proof verification using gnark
- **Artifact Caching**: Downloads cached by URL hash for performance
=======
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
>>>>>>> 8764374 (feat: add verifier server)
