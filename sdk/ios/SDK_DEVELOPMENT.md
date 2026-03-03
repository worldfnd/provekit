# ProveKit iOS SDK - Development Documentation

## Overview

This document describes the iOS SDK implementation for ProveKit, enabling mobile developers to generate and verify zero-knowledge proofs on iOS devices.

## Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                     Swift Application                        │
├─────────────────────────────────────────────────────────────┤
│                    ProveKit Swift SDK                        │
│  ┌─────────┐  ┌──────────┐  ┌───────┐  ┌──────────────┐    │
│  │ Prover  │  │ Verifier │  │ Proof │  │ ProveKitError│    │
│  └────┬────┘  └────┬─────┘  └───┬───┘  └──────────────┘    │
│       │            │            │                           │
│       └────────────┴────────────┘                           │
│                    │                                        │
│              ┌─────┴─────┐                                  │
│              │ FFIBridge │                                  │
│              └─────┬─────┘                                  │
├────────────────────┼────────────────────────────────────────┤
│              ProveKitFFI.xcframework                        │
│         (Native Rust compiled for iOS/macOS)                │
├─────────────────────────────────────────────────────────────┤
│                   provekit-ffi (Rust)                       │
│  ┌──────────────┐  ┌────────────────┐  ┌─────────────┐     │
│  │ProverHandle  │  │VerifierHandle  │  │  FFI Funcs  │     │
│  └──────────────┘  └────────────────┘  └─────────────┘     │
├─────────────────────────────────────────────────────────────┤
│                  provekit-common (Rust)                     │
│           (Prover, Verifier, NoirProof, etc.)               │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Handle-based API**: Prover and Verifier use opaque handles to manage Rust objects from Swift
2. **Single-use Verifier**: Verifier is consumed after verification (security measure)
3. **Reusable Prover**: Prover can generate multiple proofs without reloading
4. **JSON Input Format**: Inputs are passed as JSON, converted to TOML internally
5. **Binary Proof Format**: Proofs use efficient binary serialization (postcard + zstd)

## Components

### 1. FFI Layer (`tooling/provekit-ffi/`)

#### New Files Created
- `src/handles.rs` - ProverHandle and VerifierHandle for safe memory management
- `src/utils.rs` - JSON to TOML conversion utility
- `include/module.modulemap` - Swift module map for C headers

#### Modified Files
- `src/ffi.rs` - Added handle-based prover/verifier functions
- `src/types.rs` - Added new error codes
- `include/provekit_ffi.h` - C header declarations
- `Cargo.toml` - Added `toml` dependency

#### FFI Functions

```c
// Initialization
int32_t pk_init(void);

// Prover Operations
ProverHandle* pk_prover_load(const uint8_t* data, size_t len, char** error);
ProverHandle* pk_prover_load_file(const char* path, char** error);
int32_t pk_prover_prove(ProverHandle* prover, const char* inputs_json,
                        uint8_t** proof_out, size_t* proof_len, char** error);
void pk_prover_free(ProverHandle* prover);

// Verifier Operations  
VerifierHandle* pk_verifier_load(const uint8_t* data, size_t len, char** error);
VerifierHandle* pk_verifier_load_file(const char* path, char** error);
int32_t pk_verifier_verify(VerifierHandle* verifier, const uint8_t* proof,
                           size_t proof_len, char** error);
void pk_verifier_free(VerifierHandle* verifier);

// Proof Utilities
int32_t pk_proof_get_public_inputs(const uint8_t* proof, size_t proof_len,
                                   char** json_out, char** error);

// Memory Management
void pk_free_string(char* ptr);
void pk_free_bytes(uint8_t* ptr, size_t len);
```

### 2. Common Library Extensions (`provekit/common/src/file/`)

Added byte-based serialization functions:

```rust
pub fn read_from_bytes<T: FileFormat>(bytes: &[u8]) -> Result<T>
pub fn write_to_bytes<T: FileFormat>(value: &T) -> Result<Vec<u8>>
```

### 3. Swift SDK (`sdk/ios/ProveKitSDK/`)

#### Package Structure
```
ProveKitSDK/
├── Package.swift
├── README.md
├── ProveKitFFI.xcframework/
│   ├── ios-arm64/
│   ├── ios-arm64_x86_64-simulator/
│   └── macos-arm64_x86_64/
├── Sources/ProveKitSDK/
│   ├── ProveKit.swift          # Initialization
│   ├── Prover.swift            # Proof generation
│   ├── Verifier.swift          # Proof verification
│   ├── Proof.swift             # Proof data container
│   ├── ProveKitError.swift     # Error types
│   └── Internal/
│       └── FFIBridge.swift     # C FFI wrapper
└── Tests/ProveKitSDKTests/
    ├── ProveKitTests.swift
    └── Fixtures/
        ├── test.pkp
        ├── test.pkv
        └── test.np
```

#### Public API

```swift
// Initialize (call once at app startup)
try ProveKit.initialize()

// Load prover from URL or Data
let prover = try Prover(pkpURL: url)
let prover = try Prover(pkpData: data)

// Generate proof
let proof = try prover.prove(inputs: [
    "secret": 42,
    "hash": "0x1234..."
])

// Load verifier
let verifier = try Verifier(pkvURL: url)

// Verify proof
try verifier.verify(proof)
print(verifier.isConsumed) // true

// Extract public inputs
let publicInputs = try proof.publicInputs()
```

### 4. Build Scripts (`sdk/ios/scripts/`)

#### build-xcframework.sh
Builds the XCFramework for all target platforms:
- iOS device (arm64)
- iOS Simulator (arm64 + x86_64)
- macOS (arm64 + x86_64)

### 5. Example App (`sdk/ios/Examples/ProveKitDemo/`)

A complete SwiftUI demo app showing:
- Loading PKP/PKV from app bundle
- Generating proofs with custom inputs
- Verifying proofs
- Error handling UI

## File Formats

| Extension | Type | Description |
|-----------|------|-------------|
| `.pkp` | Prover Key | Contains proving key and circuit (XZ compressed) |
| `.pkv` | Verifier Key | Contains verification key (Zstd compressed) |
| `.np` | Proof | Serialized proof data (Zstd compressed) |

All files use a common header format:
```
[8 bytes] Magic: 0xDC 0xDF "OZkp" 0x01 0x00
[8 bytes] Format identifier (e.g., "PrvKitPr", "NPSProof")
[2 bytes] Major version (little-endian)
[2 bytes] Minor version (little-endian)
[...] Compressed data
```

## Testing

### Rust FFI Tests
```bash
# Run in release mode (required due to debug/release serialization difference)
cargo test -p provekit-ffi --release
```

**15 tests covering:**
- Prover load/prove operations
- Verifier load/verify operations
- Proof deserialization
- Error handling
- End-to-end prove → verify flow

### Swift SDK Tests
```bash
cd sdk/ios/ProveKitSDK
swift test
```

**12 tests covering:**
- Prover initialization
- Verifier initialization
- Proof loading
- Verification flow
- Error cases
- End-to-end test

## Known Issues

### Debug vs Release Mode Deserialization

The `WhirR1CSProof` struct contains a conditional field:
```rust
#[cfg(debug_assertions)]
#[serde(default, skip_serializing)]
pub pattern: Vec<Interaction>,
```

**Impact**: Proofs generated in release mode cannot be deserialized in debug mode.

**Workaround**: Always run tests with `--release` flag.

## Build Instructions

### Building XCFramework

```bash
cd sdk/ios/scripts
./build-xcframework.sh
```

This creates `ProveKitFFI.xcframework` in `sdk/ios/ProveKitSDK/`.

### Building Example App

```bash
cd sdk/ios/Examples/ProveKitDemo
xcodebuild -project ProveKitDemo.xcodeproj \
  -scheme ProveKitDemo \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

## Integration Guide

### Swift Package Manager

```swift
// Package.swift
dependencies: [
    .package(path: "path/to/provekit/sdk/ios/ProveKitSDK")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: ["ProveKit"]
    )
]
```

### Xcode Project

1. File → Add Package Dependencies
2. Click "Add Local..."
3. Select `sdk/ios/ProveKitSDK` directory

## Performance Considerations

- **Memory**: Provers are memory-intensive (~200-500MB depending on circuit)
- **CPU**: Proof generation is CPU-bound, runs synchronously
- **Storage**: PKP files range from 600 bytes to 12KB+ depending on circuit complexity

## Future Improvements

1. **Async API**: Add Swift async/await support for proof generation
2. **Progress Callbacks**: Report proof generation progress
3. **Android SDK**: Kotlin/Java bindings using same FFI layer
4. **Circuit Metadata**: Expose circuit information (constraints, variables)
5. **Batch Verification**: Verify multiple proofs efficiently

## Contributors

- ProveKit Team

## License

MIT License
