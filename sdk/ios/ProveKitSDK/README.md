# ProveKit iOS SDK

A Swift SDK for generating and verifying zero-knowledge proofs on iOS devices.

## Requirements

- iOS 15.0+
- macOS 12.0+ (for development)
- Xcode 15.0+
- Swift 5.9+

## Installation

### Building the XCFramework

First, build the native library:

```bash
cd sdk/ios/scripts
./build-xcframework.sh
```

This will create `ProveKitFFI.xcframework` in the `ProveKitSDK` directory.

### Adding to Your Project

#### Swift Package Manager

Add the local package to your Xcode project:

1. File → Add Package Dependencies
2. Click "Add Local..."
3. Select the `sdk/ios/ProveKitSDK` directory

Or add to your `Package.swift`:

```swift
dependencies: [
    .package(path: "../path/to/provekit/sdk/ios/ProveKitSDK")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: ["ProveKit"]
    )
]
```

## Usage

### Initialize ProveKit

Call this once at app startup:

```swift
import ProveKit

try ProveKit.initialize()
```

### Load Keys and Generate Proofs

```swift
// Load prover key from bundled resource
let pkpURL = Bundle.main.url(forResource: "circuit", withExtension: "pkp")!
let prover = try Prover(pkpURL: pkpURL)

// Generate proof with inputs
let proof = try prover.prove(inputs: [
    "secret": "42",
    "public_hash": "0x1234..."
])

// Get the serialized proof data
let proofData = try proof.serialized()
```

### Verify Proofs

```swift
// Load verifier key
let pkvURL = Bundle.main.url(forResource: "circuit", withExtension: "pkv")!
let verifier = try Verifier(pkvURL: pkvURL)

// Verify the proof
try verifier.verify(proof)

// Note: verifier is consumed after verification
print(verifier.isConsumed) // true
```

### Load from Data

You can also load keys from `Data` objects:

```swift
// Download or fetch key data
let pkpData = try await fetchProverKey()
let prover = try Prover(pkpData: pkpData)

let pkvData = try await fetchVerifierKey()
let verifier = try Verifier(pkvData: pkvData)
```

### Extract Public Inputs

```swift
let publicInputs = try proof.publicInputs()
for input in publicInputs {
    print(input)
}
```

## Error Handling

All operations throw `ProveKitError`:

```swift
do {
    let prover = try Prover(pkpURL: url)
    let proof = try prover.prove(inputs: inputs)
} catch ProveKitError.notInitialized {
    // Call ProveKit.initialize() first
} catch ProveKitError.proverLoadFailed(let message) {
    print("Failed to load prover: \(message)")
} catch ProveKitError.proveFailed(let message) {
    print("Proof generation failed: \(message)")
} catch {
    print("Unexpected error: \(error)")
}
```

## File Formats

| Extension | Description |
|-----------|-------------|
| `.pkp` | Prover key (contains proving key and circuit) |
| `.pkv` | Verifier key (contains verification key) |
| `.np` | Serialized proof (can be sent over network) |

## Thread Safety

- `Prover` can generate multiple proofs and is thread-safe for concurrent calls
- `Verifier` is single-use and is consumed after one verification
- All FFI calls are synchronized internally

## License

MIT License
