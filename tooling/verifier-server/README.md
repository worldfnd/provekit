# ProveKit Verifier Server

HTTP server combining Rust (API) + Go (verifier binary) for WHIR-based proof verification.

## Quick Start

```bash
cd tooling/verifier-server
docker-compose up --build
```

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
    "npsUrl": "https://example.com/scheme.nps",
    "r1csUrl": "https://example.com/r1cs.json", 
    "pkUrl": "https://example.com/proving_key.bin", (optional)
    "vkUrl": "https://example.com/verification_key.bin", (optional)
    "np": { /* NoirProof JSON */ },
  }'
```

**Response:**
```json
{
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
