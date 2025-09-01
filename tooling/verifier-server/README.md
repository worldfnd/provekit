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
    "pkUrl": "https://example.com/proving_key.bin",
    "vkUrl": "https://example.com/verification_key.bin",
    "np": { /* NoirProof JSON */ },
    "verificationParams": { "maxVerificationTime": 300 }
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

- `VERIFIER_HOST`, `VERIFIER_PORT` - Server binding
- `VERIFIER_BINARY_PATH` - Go verifier path  
- `VERIFIER_ARTIFACTS_DIR` - Cache directory
- `RUST_LOG` - Log level (default: `info`)

## Architecture

- **Rust HTTP Server**: Handles requests, downloads artifacts, orchestrates verification
- **Go Verifier Binary**: Performs WHIR proof verification using gnark
- **Artifact Caching**: Downloads cached by URL hash for performance
