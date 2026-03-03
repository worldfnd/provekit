# ProveKit iOS SDK - Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              iOS Application                                 │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         Application Layer                               │ │
│  │                                                                         │ │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │ │
│  │   │   UI/UX     │    │  Business   │    │   Storage   │               │ │
│  │   │  (SwiftUI)  │◄──►│   Logic     │◄──►│  (Files/    │               │ │
│  │   │             │    │             │    │   Keychain) │               │ │
│  │   └─────────────┘    └──────┬──────┘    └─────────────┘               │ │
│  │                             │                                          │ │
│  └─────────────────────────────┼──────────────────────────────────────────┘ │
│                                │                                             │
│  ┌─────────────────────────────▼──────────────────────────────────────────┐ │
│  │                      ProveKit Swift SDK                                 │ │
│  │                                                                         │ │
│  │   ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌─────────────┐  │ │
│  │   │  ProveKit │    │  Prover   │    │ Verifier  │    │    Proof    │  │ │
│  │   │  (init)   │    │           │    │           │    │             │  │ │
│  │   └───────────┘    └─────┬─────┘    └─────┬─────┘    └──────┬──────┘  │ │
│  │                          │                │                  │         │ │
│  │                          └────────────────┼──────────────────┘         │ │
│  │                                           │                            │ │
│  │   ┌───────────────────────────────────────▼────────────────────────┐  │ │
│  │   │                        FFIBridge                                │  │ │
│  │   │                   (Internal - unsafe)                           │  │ │
│  │   │                                                                 │  │ │
│  │   │  • Memory management (alloc/free)                              │  │ │
│  │   │  • Error translation                                           │  │ │
│  │   │  • Type marshalling (Swift ↔ C)                                │  │ │
│  │   └─────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                           │                                  │
├───────────────────────────────────────────┼──────────────────────────────────┤
│                                           │                                  │
│  ┌────────────────────────────────────────▼───────────────────────────────┐ │
│  │                     ProveKitFFI.xcframework                             │ │
│  │                                                                         │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │ │
│  │  │   ios-arm64     │  │ ios-simulator   │  │   macos-universal       │ │ │
│  │  │   (Device)      │  │ (arm64+x86_64)  │  │   (arm64+x86_64)        │ │ │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────┘ │ │
│  │                                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                           │                                  │
├───────────────────────────────────────────┼──────────────────────────────────┤
│                                           │                                  │
│  ┌────────────────────────────────────────▼───────────────────────────────┐ │
│  │                         Rust Native Layer                               │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                      provekit-ffi                                │   │ │
│  │  │                                                                  │   │ │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │   │ │
│  │  │  │ ProverHandle │  │VerifierHandle│  │     FFI Functions      │ │   │ │
│  │  │  │              │  │              │  │                        │ │   │ │
│  │  │  │ • load()     │  │ • load()     │  │ • pk_init()            │ │   │ │
│  │  │  │ • prove()    │  │ • verify()   │  │ • pk_prover_*()        │ │   │ │
│  │  │  │ • free()     │  │ • free()     │  │ • pk_verifier_*()      │ │   │ │
│  │  │  └──────────────┘  └──────────────┘  │ • pk_proof_*()         │ │   │ │
│  │  │                                       │ • pk_free_*()          │ │   │ │
│  │  │                                       └────────────────────────┘ │   │ │
│  │  └──────────────────────────────────────────────────────────────────┘   │ │
│  │                                    │                                    │ │
│  │  ┌─────────────────────────────────▼────────────────────────────────┐  │ │
│  │  │                     provekit-prover                               │  │ │
│  │  │                     provekit-verifier                             │  │ │
│  │  │                     provekit-common                               │  │ │
│  │  └──────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagrams

### 1. Proof Generation Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│     App      │     │  Swift SDK   │     │   Rust FFI   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Load PKP       │                    │
       │───────────────────►│                    │
       │                    │  2. pk_prover_load │
       │                    │───────────────────►│
       │                    │                    │ 3. Deserialize
       │                    │                    │    & allocate
       │                    │  4. ProverHandle   │
       │                    │◄───────────────────│
       │  5. Prover         │                    │
       │◄───────────────────│                    │
       │                    │                    │
       │  6. prove(inputs)  │                    │
       │───────────────────►│                    │
       │                    │  7. JSON encode    │
       │                    │                    │
       │                    │  8. pk_prover_prove│
       │                    │───────────────────►│
       │                    │                    │ 9. JSON→TOML
       │                    │                    │ 10. Generate
       │                    │                    │     proof
       │                    │                    │ 11. Serialize
       │                    │  12. proof bytes   │
       │                    │◄───────────────────│
       │  13. Proof         │                    │
       │◄───────────────────│                    │
       │                    │                    │
       ▼                    ▼                    ▼
```

### 2. Verification Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│     App      │     │  Swift SDK   │     │   Rust FFI   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Load PKV       │                    │
       │───────────────────►│                    │
       │                    │  2. pk_verifier_load
       │                    │───────────────────►│
       │                    │                    │ 3. Deserialize
       │                    │  4. VerifierHandle │
       │                    │◄───────────────────│
       │  5. Verifier       │                    │
       │◄───────────────────│                    │
       │                    │                    │
       │  6. verify(proof)  │                    │
       │───────────────────►│                    │
       │                    │  7. Check consumed │
       │                    │                    │
       │                    │  8. pk_verifier_verify
       │                    │───────────────────►│
       │                    │                    │ 9. Deserialize
       │                    │                    │    proof
       │                    │                    │ 10. Verify
       │                    │                    │ 11. Mark consumed
       │                    │  12. Result        │
       │                    │◄───────────────────│
       │                    │  13. Set isConsumed│
       │  14. Success/Error │                    │
       │◄───────────────────│                    │
       │                    │                    │
       ▼                    ▼                    ▼
```

### 3. Memory Management Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Memory Lifecycle                              │
└─────────────────────────────────────────────────────────────────────┘

  Swift Side                              Rust Side
  ──────────                              ─────────

  ┌─────────────┐                         ┌─────────────┐
  │ Prover()    │ ──── pk_prover_load ───►│ Box::new()  │
  │ init        │                         │ Allocate    │
  └─────────────┘                         └──────┬──────┘
        │                                        │
        │  Holds OpaquePointer                   │ Returns *mut
        │                                        │
        ▼                                        ▼
  ┌─────────────┐                         ┌─────────────┐
  │   prove()   │ ──── pk_prover_prove ──►│ Clone &     │
  │   (reuse)   │                         │ generate    │
  └─────────────┘                         └─────────────┘
        │                                        │
        │  proof bytes returned                  │ Allocate Vec<u8>
        │                                        │
        ▼                                        ▼
  ┌─────────────┐                         ┌─────────────┐
  │ Data(bytes) │◄── copy to Swift Data ──│ proof_out   │
  │             │                         │             │
  └─────────────┘                         └──────┬──────┘
        │                                        │
        │                                        │
        ▼                                        ▼
  ┌─────────────┐                         ┌─────────────┐
  │  deinit     │ ──── pk_free_bytes ────►│ Vec::drop() │
  │             │                         │             │
  └─────────────┘                         └─────────────┘
        │                                        │
        │                                        │
        ▼                                        ▼
  ┌─────────────┐                         ┌─────────────┐
  │  deinit     │ ──── pk_prover_free ───►│ Box::drop() │
  │  Prover     │                         │ Deallocate  │
  └─────────────┘                         └─────────────┘
```

---

## Component Details

### Swift SDK Layer

```
ProveKitSDK/
├── Sources/ProveKitSDK/
│   ├── ProveKit.swift          # Static initialization
│   ├── Prover.swift            # Proof generation
│   ├── Verifier.swift          # Proof verification (single-use)
│   ├── Proof.swift             # Proof container
│   ├── ProveKitError.swift     # Error types
│   └── Internal/
│       └── FFIBridge.swift     # C interop (unsafe)
└── Tests/
    └── ProveKitSDKTests/
        └── ProveKitTests.swift # Unit tests
```

#### Class Responsibilities

| Class | Responsibility | Thread Safety |
|-------|----------------|---------------|
| `ProveKit` | Runtime initialization | Thread-safe (idempotent) |
| `Prover` | Load PKP, generate proofs | Reusable, not thread-safe |
| `Verifier` | Load PKV, verify proofs | Single-use, consumed after verify |
| `Proof` | Hold serialized proof data | Immutable, thread-safe |
| `FFIBridge` | C function calls, memory mgmt | Internal only |

### Rust FFI Layer

```
provekit-ffi/
├── src/
│   ├── lib.rs              # Exports
│   ├── ffi.rs              # C-compatible functions
│   ├── handles.rs          # ProverHandle, VerifierHandle
│   ├── types.rs            # PKError, PKBuf
│   └── utils.rs            # JSON→TOML conversion
└── include/
    ├── provekit_ffi.h      # C header
    └── module.modulemap    # Swift module map
```

#### FFI Function Categories

| Category | Functions | Purpose |
|----------|-----------|---------|
| Init | `pk_init` | Initialize runtime |
| Prover | `pk_prover_load`, `pk_prover_load_file`, `pk_prover_prove`, `pk_prover_free` | Proof generation |
| Verifier | `pk_verifier_load`, `pk_verifier_load_file`, `pk_verifier_verify`, `pk_verifier_free` | Verification |
| Proof | `pk_proof_get_public_inputs` | Proof utilities |
| Memory | `pk_free_string`, `pk_free_bytes` | Cleanup |

---

## File Format Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         File Structure                               │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                        Binary File Header                         │
├──────────┬──────────┬────────────────────────────────────────────┤
│  Offset  │   Size   │                Description                 │
├──────────┼──────────┼────────────────────────────────────────────┤
│   0x00   │    8     │  Magic: 0xDC 0xDF "OZkp" 0x01 0x00        │
│   0x08   │    8     │  Format ID (ASCII, e.g., "PrvKitPr")       │
│   0x10   │    2     │  Major version (uint16 LE)                 │
│   0x12   │    2     │  Minor version (uint16 LE)                 │
│   0x14   │   ...    │  Compressed payload (Zstd or XZ)           │
└──────────┴──────────┴────────────────────────────────────────────┘

File Types:
┌────────────┬────────────┬─────────────┬──────────────────────────┐
│ Extension  │ Format ID  │ Compression │        Contents          │
├────────────┼────────────┼─────────────┼──────────────────────────┤
│   .pkp     │ PrvKitPr   │     XZ      │ Prover key + circuit     │
│   .pkv     │ PrvKitVr   │    Zstd     │ Verifier key             │
│   .np      │ NPSProof   │    Zstd     │ Serialized proof         │
└────────────┴────────────┴─────────────┴──────────────────────────┘
```

---

## Error Handling Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Error Propagation                               │
└─────────────────────────────────────────────────────────────────────┘

  Rust Core              Rust FFI                 Swift SDK
  ─────────              ────────                 ─────────

  ┌─────────────┐       ┌─────────────┐         ┌─────────────┐
  │ anyhow::Error│──────►│  PKError    │────────►│ProveKitError│
  │             │       │  (C enum)   │         │ (Swift enum)│
  └─────────────┘       └─────────────┘         └─────────────┘
        │                     │                       │
        │                     │                       │
        ▼                     ▼                       ▼
  ┌─────────────┐       ┌─────────────┐         ┌─────────────┐
  │ Result<T,E> │       │ return code │         │ throws      │
  │             │       │ + error ptr │         │             │
  └─────────────┘       └─────────────┘         └─────────────┘

Error Codes (PKError):
┌───────┬─────────────────────┬────────────────────────────────────┐
│ Code  │        Name         │            Description             │
├───────┼─────────────────────┼────────────────────────────────────┤
│   0   │ Success             │ Operation completed                │
│   1   │ InvalidInput        │ Bad parameters                     │
│   2   │ SchemeReadError     │ Failed to read PKP/PKV             │
│   3   │ WitnessReadError    │ Failed to read inputs              │
│   4   │ ProofError          │ Proof generation failed            │
│   5   │ SerializationError  │ Encoding failed                    │
│   6   │ Utf8Error           │ String conversion failed           │
│   7   │ FileWriteError      │ File I/O failed                    │
│   8   │ VerificationFailed  │ Invalid proof                      │
│   9   │ VerifierConsumed    │ Verifier already used              │
│  10   │ DeserializationError│ Decoding failed                    │
└───────┴─────────────────────┴────────────────────────────────────┘
```

---

## Build Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Build Pipeline                                │
└─────────────────────────────────────────────────────────────────────┘

                    build-xcframework.sh
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │ iOS Device │  │ Simulator  │  │   macOS    │
    │  (arm64)   │  │(arm64+x86) │  │(arm64+x86) │
    └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
          │               │               │
          │  cargo build --target ...     │
          │               │               │
          ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │libprovekit │  │libprovekit │  │libprovekit │
    │  _ffi.a    │  │  _ffi.a    │  │  _ffi.a    │
    └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
          │               │               │
          │  lipo (combine simulators)    │
          │               │               │
          └───────────────┼───────────────┘
                          │
                          ▼
                 ┌────────────────┐
                 │  xcodebuild    │
                 │  -create-      │
                 │  xcframework   │
                 └────────┬───────┘
                          │
                          ▼
              ┌───────────────────────┐
              │ ProveKitFFI.xcframework│
              │                       │
              │ ├── ios-arm64/        │
              │ ├── ios-simulator/    │
              │ └── macos-universal/  │
              └───────────────────────┘
```

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Security Boundaries                              │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                        Swift (Safe)                                  │
│                                                                      │
│  • Type-safe API                                                    │
│  • No raw pointers exposed                                          │
│  • Error handling via throws                                        │
│  • Single-use verifier enforced                                     │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                      FFIBridge (Controlled Unsafe)                   │
│                                                                      │
│  • withUnsafeBytes for data access                                  │
│  • OpaquePointer for handles                                        │
│  • Explicit memory freeing                                          │
│  • Error pointer handling                                           │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                        Rust (Memory Safe)                            │
│                                                                      │
│  • Ownership-based memory management                                │
│  • Panic catching at FFI boundary                                   │
│  • No undefined behavior                                            │
│  • Box/Vec for allocations                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

Security Properties:
┌─────────────────────────────────────────────────────────────────────┐
│ Property              │ Mechanism                                   │
├───────────────────────┼─────────────────────────────────────────────┤
│ Memory safety         │ Rust ownership + Swift ARC                  │
│ No use-after-free     │ Handle invalidation, consumed flag          │
│ No double-free        │ Single ownership transfer                   │
│ Panic safety          │ catch_unwind at FFI boundary                │
│ Thread safety         │ No shared mutable state (verifier consumed) │
│ Zero-knowledge        │ Cryptographic proof system                  │
└───────────────────────┴─────────────────────────────────────────────┘
```

---

## Integration Points

```
┌─────────────────────────────────────────────────────────────────────┐
│                    App Integration Points                            │
└─────────────────────────────────────────────────────────────────────┘

1. Initialization (AppDelegate / App struct)
   ┌─────────────────────────────────────────┐
   │  @main                                  │
   │  struct MyApp: App {                    │
   │      init() {                           │
   │          try? ProveKit.initialize()     │  ◄── Call once
   │      }                                  │
   │  }                                      │
   └─────────────────────────────────────────┘

2. Key Loading (Bundle / Network / Secure Storage)
   ┌─────────────────────────────────────────┐
   │  // From bundle                         │
   │  let url = Bundle.main.url(...)         │
   │  let prover = try Prover(pkpURL: url)   │
   │                                         │
   │  // From network                        │
   │  let data = try await fetch(...)        │
   │  let prover = try Prover(pkpData: data) │
   │                                         │
   │  // From Keychain                       │
   │  let data = keychain.getData(...)       │
   │  let prover = try Prover(pkpData: data) │
   └─────────────────────────────────────────┘

3. Proof Generation (Background Thread)
   ┌─────────────────────────────────────────┐
   │  Task.detached {                        │
   │      let proof = try prover.prove(      │  ◄── CPU intensive
   │          inputs: [...]                  │
   │      )                                  │
   │      await MainActor.run {              │
   │          self.proof = proof             │
   │      }                                  │
   │  }                                      │
   └─────────────────────────────────────────┘

4. Verification (Fresh Verifier Each Time)
   ┌─────────────────────────────────────────┐
   │  let verifier = try Verifier(...)       │  ◄── New instance
   │  try verifier.verify(proof)             │  ◄── Consumes verifier
   │  // verifier.isConsumed == true         │
   └─────────────────────────────────────────┘

5. Proof Transmission
   ┌─────────────────────────────────────────┐
   │  // Send to server                      │
   │  let data = proof.serializedData        │
   │  try await api.submitProof(data)        │
   │                                         │
   │  // Save locally                        │
   │  try data.write(to: fileURL)            │
   └─────────────────────────────────────────┘
```
