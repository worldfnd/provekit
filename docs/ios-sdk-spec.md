# ProveKit iOS SDK — Technical Specification

**Version:** 1.0  
**Date:** March 2025  
**Status:** Implementation Complete  
**Author:** ProveKit Mobile Team

---

## Executive Summary

This document specifies the design and implementation of the ProveKit iOS SDK, enabling mobile applications to generate and verify zero-knowledge proofs on iOS devices. The SDK provides a native Swift interface that wraps our high-performance Rust proving system, allowing iOS developers to integrate privacy-preserving cryptographic proofs with minimal complexity.

### Project Status

| Component | Status | Notes |
|-----------|--------|-------|
| Rust FFI Layer | ✅ Complete | Handle-based API with full error handling |
| Swift SDK | ✅ Complete | Native Swift 5.9+ API |
| XCFramework | ✅ Complete | iOS device, simulator, macOS |
| Test Suite | ✅ Complete | 27 tests passing |
| Example App | ✅ Complete | SwiftUI demo with full flow |
| Documentation | ✅ Complete | API docs, integration guide, spec |

### Key Capabilities

- **Proof Generation**: Generate ZK proofs locally on iOS devices
- **Proof Verification**: Verify proofs without revealing private inputs
- **Simple Integration**: 3-step flow — Load → Prove → Verify
- **Production Ready**: Comprehensive error handling, memory safety, test coverage

---

## 1. Introduction

### 1.1 Purpose

The ProveKit iOS SDK enables mobile applications to leverage zero-knowledge proofs for privacy-preserving computations. Use cases include:

- Identity verification without revealing personal data
- Private credential systems
- Confidential financial transactions
- Secure voting and attestation systems

### 1.2 Target Audience

| Audience | Usage |
|----------|-------|
| iOS Developers | Integrate SDK into mobile apps |
| Security Engineers | Review cryptographic implementation |
| Product Managers | Understand capabilities and limitations |
| DevOps | Build and deployment processes |

### 1.3 Scope

**In Scope:**
- iOS 15.0+ and macOS 12.0+ support
- Swift Package Manager distribution
- Synchronous proving and verification API
- Binary proof serialization format

**Out of Scope (Future Versions):**
- Android SDK
- Async/concurrent API
- On-device circuit compilation
- Network proof submission

---

## 2. Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        iOS Application                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ┌──────────────────────────────────────────────────────┐     │
│    │                 ProveKit Swift SDK                    │     │
│    │                                                       │     │
│    │   ┌─────────┐   ┌──────────┐   ┌───────┐            │     │
│    │   │ Prover  │   │ Verifier │   │ Proof │            │     │
│    │   └────┬────┘   └────┬─────┘   └───┬───┘            │     │
│    │        │             │             │                 │     │
│    │        └─────────────┼─────────────┘                 │     │
│    │                      │                               │     │
│    │                ┌─────┴─────┐                         │     │
│    │                │ FFIBridge │                         │     │
│    │                └─────┬─────┘                         │     │
│    └──────────────────────┼───────────────────────────────┘     │
│                           │                                      │
├───────────────────────────┼──────────────────────────────────────┤
│                           │                                      │
│    ┌──────────────────────▼───────────────────────────────┐     │
│    │              ProveKitFFI.xcframework                  │     │
│    │                                                       │     │
│    │    ios-arm64  │  ios-simulator  │  macos-universal   │     │
│    └───────────────────────────────────────────────────────┘     │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                        Rust Core                                 │
│                                                                  │
│    provekit-ffi  →  provekit-prover  →  provekit-common         │
│                     provekit-verifier                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **Swift SDK** | Public API, type safety, Swift idioms |
| **FFIBridge** | C interop, memory management, error translation |
| **XCFramework** | Platform-specific native binaries |
| **provekit-ffi** | C ABI, handle management, panic safety |
| **provekit-prover** | Zero-knowledge proof generation |
| **provekit-verifier** | Proof verification |
| **provekit-common** | Shared types, serialization |

### 2.3 Data Flow

```
                    ┌─────────────┐
                    │   Inputs    │
                    │   (JSON)    │
                    └──────┬──────┘
                           │
    ┌──────────────┐       │       ┌──────────────┐
    │  Prover Key  │       │       │ Verifier Key │
    │    (.pkp)    │       │       │    (.pkv)    │
    └──────┬───────┘       │       └──────┬───────┘
           │               │               │
           ▼               ▼               ▼
    ┌──────────────────────────────────────────────┐
    │                   Prover                      │
    │              prover.prove(inputs)             │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Proof     │
                    │    (.np)     │
                    └──────┬───────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │                  Verifier                     │
    │              verifier.verify(proof)           │
    │                 (consumed)                    │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Result    │
                    │  ✓ Valid     │
                    │  ✗ Invalid   │
                    └──────────────┘
```

---

## 3. Public API

### 3.1 ProveKit (Initialization)

```swift
import ProveKit

// Initialize runtime (call once at app startup)
try ProveKit.initialize()
```

| Method | Description |
|--------|-------------|
| `initialize()` | Initialize ProveKit runtime. Thread-safe, idempotent. |

### 3.2 Prover

```swift
public final class Prover {
    /// Load from in-memory data
    public init(pkpData: Data) throws
    
    /// Load from file URL  
    public init(pkpURL: URL) throws
    
    /// Generate proof (reusable - can call multiple times)
    public func prove(inputs: [String: Any]) throws -> Proof
}
```

**Usage:**
```swift
let prover = try Prover(pkpURL: pkpURL)

// Generate multiple proofs with same prover
let proof1 = try prover.prove(inputs: ["x": 1, "y": 2])
let proof2 = try prover.prove(inputs: ["x": 3, "y": 4])
```

### 3.3 Verifier

```swift
public final class Verifier {
    /// Load from in-memory data
    public init(pkvData: Data) throws
    
    /// Load from file URL
    public init(pkvURL: URL) throws
    
    /// Check if consumed
    public private(set) var isConsumed: Bool
    
    /// Verify proof (single-use - consumes verifier)
    public func verify(_ proof: Proof) throws
}
```

**Usage:**
```swift
let verifier = try Verifier(pkvURL: pkvURL)
try verifier.verify(proof)
// verifier.isConsumed == true
// Cannot call verify() again
```

**Security Design:** Verifiers are single-use by design. This prevents replay attacks and ensures cryptographic freshness.

### 3.4 Proof

```swift
public struct Proof: Equatable {
    /// Raw serialized proof bytes
    public let serializedData: Data
    
    /// Create from serialized data
    public init(serializedData: Data) throws
    
    /// Load from file
    public init(proofURL: URL) throws
    
    /// Extract public inputs
    public func publicInputs() throws -> [[String: Any]]
}
```

**Usage:**
```swift
// Save proof
try proof.serializedData.write(to: fileURL)

// Load proof
let loadedProof = try Proof(proofURL: fileURL)

// Get public inputs
let inputs = try proof.publicInputs()
```

### 3.5 Error Handling

```swift
public enum ProveKitError: Error {
    case notInitialized              // ProveKit.initialize() not called
    case initializationFailed        // Runtime init failed
    case proverLoadFailed(String)    // Invalid PKP
    case verifierLoadFailed(String)  // Invalid PKV
    case proveFailed(String)         // Proof generation failed
    case verificationFailed(String)  // Invalid proof
    case verifierConsumed            // Verifier already used
    case serializationFailed(String) // Encoding error
    case deserializationFailed(String) // Decoding error
    case invalidInput(String)        // Bad input data
    case ffiError(code: Int32, message: String) // Low-level error
}
```

---

## 4. File Formats

### 4.1 Format Summary

| Extension | Name | Description | Compression | Size Range |
|-----------|------|-------------|-------------|------------|
| `.pkp` | Prover Key | Proving key + circuit | XZ (LZMA2) | 500B – 50KB |
| `.pkv` | Verifier Key | Verification parameters | Zstd | 400B – 10KB |
| `.np` | Proof | Serialized ZK proof | Zstd | 1MB – 2MB |

### 4.2 Binary Header

All files share a 20-byte header:

```
Offset  Size  Field
──────  ────  ─────────────────────
0x00    8     Magic: DC DF "OZkp" 01 00
0x08    8     Format ID (ASCII)
0x10    2     Major version (LE)
0x12    2     Minor version (LE)
0x14    ...   Compressed payload
```

**Format IDs:**
- `PrvKitPr` — Prover Key
- `PrvKitVr` — Verifier Key  
- `NPSProof` — Proof

---

## 5. Integration Guide

### 5.1 Installation

**Swift Package Manager:**

```swift
// Package.swift
dependencies: [
    .package(path: "path/to/sdk/ios/ProveKitSDK")
]
```

**Xcode:**
1. File → Add Package Dependencies
2. Add Local → Select `sdk/ios/ProveKitSDK`

### 5.2 Complete Example

```swift
import ProveKit

class ZKProofService {
    private var prover: Prover?
    
    func setup() throws {
        // 1. Initialize (once per app launch)
        try ProveKit.initialize()
        
        // 2. Load prover key
        guard let pkpURL = Bundle.main.url(forResource: "circuit", withExtension: "pkp") else {
            throw MyError.missingKey
        }
        prover = try Prover(pkpURL: pkpURL)
    }
    
    func generateProof(secret: Int, commitment: String) throws -> Data {
        guard let prover = prover else {
            throw MyError.notSetup
        }
        
        // 3. Generate proof
        let proof = try prover.prove(inputs: [
            "secret": secret,
            "commitment": commitment
        ])
        
        return proof.serializedData
    }
    
    func verifyProof(_ proofData: Data, pkvURL: URL) throws -> Bool {
        // 4. Load verifier (new instance each time)
        let verifier = try Verifier(pkvURL: pkvURL)
        let proof = try Proof(serializedData: proofData)
        
        // 5. Verify
        do {
            try verifier.verify(proof)
            return true
        } catch ProveKitError.verificationFailed {
            return false
        }
    }
}
```

### 5.3 Best Practices

| Practice | Rationale |
|----------|-----------|
| Initialize early | Call `ProveKit.initialize()` in `application(_:didFinishLaunching)` |
| Reuse Prover | Load once, generate many proofs |
| Fresh Verifier | Create new Verifier for each verification |
| Background proving | Run `prove()` on background queue for UI responsiveness |
| Handle errors | All operations can throw — always use try/catch |

---

## 6. Performance

### 6.1 Benchmarks

*Measured on iPhone 15 Pro (A17 Pro)*

| Operation | Time | Peak Memory |
|-----------|------|-------------|
| Initialize | < 10ms | ~1 MB |
| Load Prover | 50-200ms | 100-500 MB |
| Load Verifier | 10-50ms | 10-50 MB |
| Generate Proof | 100ms - 5s | +50-200 MB |
| Verify Proof | 20-100ms | ~10 MB |

### 6.2 Resource Guidelines

**Memory:**
- Monitor `didReceiveMemoryWarning`
- Release Prover when not needed
- Proof generation is memory-intensive

**CPU:**
- Proving is CPU-bound, single-threaded
- Consider background execution
- Significant battery impact during proving

**Storage:**
- Keys are small (< 100KB)
- Proofs are larger (1-2 MB)
- Consider cleanup policies

---

## 7. Testing

### 7.1 Test Summary

| Suite | Tests | Status |
|-------|-------|--------|
| Rust FFI | 15 | ✅ Passing |
| Swift SDK | 12 | ✅ Passing |
| **Total** | **27** | ✅ All Passing |

### 7.2 Test Coverage

**Rust FFI Tests:**
- Prover load (file, bytes, invalid)
- Verifier load (file, bytes, invalid)
- Proof generation
- Verification (valid, invalid, consumed)
- End-to-end flow
- Memory management

**Swift SDK Tests:**
- API initialization
- Prover operations
- Verifier operations
- Proof serialization
- Error conditions
- End-to-end integration

### 7.3 Running Tests

```bash
# Rust tests (use --release)
cargo test -p provekit-ffi --release

# Swift tests
cd sdk/ios/ProveKitSDK && swift test
```

---

## 8. Security

### 8.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Memory disclosure | Rust memory safety, no raw pointer exposure |
| Replay attacks | Single-use verifier design |
| Side channels | Constant-time operations where applicable |
| Key theft | Keys stored in app bundle or secure enclave (app responsibility) |

### 8.2 Security Properties

- **Zero-Knowledge**: Proofs reveal nothing beyond validity
- **Soundness**: Invalid proofs cannot pass verification
- **Completeness**: Valid proofs always verify
- **Non-malleability**: Proofs cannot be modified

### 8.3 Recommendations

1. Store keys securely (Keychain, encrypted storage)
2. Validate proof sources before verification
3. Use certificate pinning for key downloads
4. Implement rate limiting for proof generation

---

## 9. Build & Distribution

### 9.1 Building XCFramework

```bash
cd sdk/ios/scripts
./build-xcframework.sh
```

**Build Targets:**
- `ios-arm64` — iPhone/iPad devices
- `ios-arm64_x86_64-simulator` — Simulator
- `macos-arm64_x86_64` — macOS development

**Output:** `sdk/ios/ProveKitSDK/ProveKitFFI.xcframework/`

### 9.2 CI/CD Integration

```yaml
# Example GitHub Actions
- name: Build XCFramework
  run: |
    cd sdk/ios/scripts
    ./build-xcframework.sh

- name: Run Swift Tests
  run: |
    cd sdk/ios/ProveKitSDK
    swift test
```

---

## 10. Limitations

### 10.1 Current Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Synchronous API | May block UI | Use background queue |
| Single-use verifier | Must reload per verification | By design |
| No progress callbacks | Can't show progress | Future enhancement |
| iOS 15+ required | No older device support | Platform minimum |

### 10.2 Known Issues

| Issue | Status | Notes |
|-------|--------|-------|
| Debug/release serialization mismatch | Documented | Run tests with `--release` |

---

## 11. Roadmap

### Completed ✅
- [x] FFI layer with handle-based API
- [x] Swift SDK with full error handling
- [x] XCFramework build system
- [x] Comprehensive test suite
- [x] Example SwiftUI application
- [x] Technical documentation

### Phase 2: Production Hardening
- [ ] Async/await API
- [ ] Progress callbacks
- [ ] Memory optimization
- [ ] Performance profiling

### Phase 3: Platform Expansion
- [ ] Android SDK (Kotlin)
- [ ] React Native bindings
- [ ] Flutter plugin

### Phase 4: Advanced Features
- [ ] Batch verification
- [ ] Proof aggregation
- [ ] Circuit metadata API

---

## 12. Appendix

### A. Directory Structure

```
sdk/ios/
├── ProveKitSDK/
│   ├── Package.swift
│   ├── README.md
│   ├── ProveKitFFI.xcframework/
│   ├── Sources/ProveKitSDK/
│   │   ├── ProveKit.swift
│   │   ├── Prover.swift
│   │   ├── Verifier.swift
│   │   ├── Proof.swift
│   │   ├── ProveKitError.swift
│   │   └── Internal/FFIBridge.swift
│   └── Tests/ProveKitSDKTests/
│       ├── ProveKitTests.swift
│       └── Fixtures/
├── Examples/ProveKitDemo/
│   ├── ProveKitDemo.xcodeproj
│   └── ProveKitDemo/
└── scripts/
    └── build-xcframework.sh
```

### B. Glossary

| Term | Definition |
|------|------------|
| ZK Proof | Zero-knowledge proof — proves statement validity without revealing inputs |
| PKP | Prover Key Package — contains proving key and circuit definition |
| PKV | Prover Verification Key — contains verification parameters |
| FFI | Foreign Function Interface — enables Rust/Swift interop |
| XCFramework | Apple's multi-platform binary distribution format |

### C. References

- ProveKit Core Documentation
- Apple Swift Package Manager Guide
- Rust FFI Best Practices

---

**Document Control**

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-03-03 | Initial release — Implementation complete |

---

*For questions, contact the ProveKit Mobile Team.*
