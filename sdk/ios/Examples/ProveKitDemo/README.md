# ProveKitDemo

A sample iOS app demonstrating the ProveKitSDK for generating and verifying zero-knowledge proofs on mobile.

## Prerequisites

1. **Xcode 15.0+** with iOS 15.0+ SDK
2. **Rust toolchain** with iOS targets:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   ```
3. **Built XCFramework** (see below)

## Setup

### 1. Build the ProveKit XCFramework

From the repository root:

```bash
cd sdk/ios/scripts
./build-xcframework.sh
```

This creates `sdk/ios/ProveKitFFI.xcframework/` containing the native library.

### 2. Open the Project

```bash
open sdk/ios/Examples/ProveKitDemo/ProveKitDemo.xcodeproj
```

### 3. Add ProveKitSDK Package Dependency

In Xcode:
1. File → Add Package Dependencies...
2. Click "Add Local..." 
3. Navigate to `sdk/ios/ProveKitSDK/`
4. Click "Add Package"

### 4. Add Test Keys to the App Bundle

The demo app expects `prover.pkp` and `verifier.pkv` files in the app bundle.

Option A - Use the basic-2 example keys:
```bash
cp noir-examples/basic-2/prover.pkp sdk/ios/Examples/ProveKitDemo/ProveKitDemo/
cp noir-examples/basic-2/verifier.pkv sdk/ios/Examples/ProveKitDemo/ProveKitDemo/
```

Then in Xcode, drag both files into the ProveKitDemo group and check "Copy items if needed".

Option B - Generate your own keys using the ProveKit CLI.

### 5. Build and Run

Select an iOS Simulator or device, then ⌘R to build and run.

## Usage

The demo app provides a simple three-step flow:

1. **Load Keys** - Tap to load the prover and verifier keys from the app bundle
2. **Generate Proof** - Creates a proof for the basic-2 circuit (proves knowledge of `a` and `b` where `a * b = c`)
3. **Verify Proof** - Verifies the generated proof using the verifier key

Each step shows a status indicator (⏳ pending, ✅ success, ❌ error).

## Customization

### Using Different Circuits

To use a different circuit:

1. Replace `prover.pkp` and `verifier.pkv` with keys for your circuit
2. Modify `ContentView.swift` to provide the correct inputs:

```swift
// Change this to match your circuit's expected inputs
let inputs: [String: Any] = [
    "your_input_name": your_value,
    // ...
]
let proof = try prover.prove(inputs: inputs)
```

### Input Types

ProveKitSDK supports these input types:
- Integers: `"field": 42`
- Strings (hex): `"hash": "0x1234..."`
- Arrays: `"values": [1, 2, 3]`
- Nested arrays: `"matrix": [[1, 2], [3, 4]]`

## Troubleshooting

### "Library not loaded" error

The XCFramework isn't linked properly. Ensure:
1. `ProveKitFFI.xcframework` exists at `sdk/ios/`
2. It's added to the ProveKitSDK package's binaryTarget

### "prover.pkp not found" error

The key files aren't in the app bundle. Follow step 4 above to add them.

### Build errors about missing symbols

Rebuild the XCFramework with `./build-xcframework.sh` and clean the Xcode build folder (⇧⌘K).

## Architecture

```
ProveKitDemo/
├── ProveKitDemoApp.swift    # App entry point
├── ContentView.swift        # Main UI with proof generation flow
└── Assets.xcassets/         # App icons and colors
```

The app uses SwiftUI and demonstrates:
- Loading keys from the bundle using `Bundle.main.url(forResource:)`
- Synchronous proof generation (runs on main thread for simplicity)
- Error handling with user-friendly messages

For production apps, consider running proof generation on a background thread to avoid blocking the UI.
