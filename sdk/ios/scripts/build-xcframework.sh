#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FFI_CRATE="$PROJECT_ROOT/tooling/provekit-ffi"
OUTPUT_DIR="$PROJECT_ROOT/sdk/ios/ProveKitSDK"

echo "📦 Building ProveKit XCFramework..."
echo "   Project root: $PROJECT_ROOT"
echo "   FFI crate: $FFI_CRATE"
echo "   Output: $OUTPUT_DIR"

# Check for required tools
if ! command -v cargo &> /dev/null; then
    echo "❌ cargo not found. Please install Rust."
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo "❌ xcodebuild not found. Please install Xcode."
    exit 1
fi

# Install iOS targets if not present
echo ""
echo "🔧 Checking Rust targets..."
rustup target add aarch64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
rustup target add x86_64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-darwin 2>/dev/null || true
rustup target add x86_64-apple-darwin 2>/dev/null || true

# Build for all iOS targets
echo ""
echo "🔨 Building for iOS device (arm64)..."
cargo build --manifest-path "$FFI_CRATE/Cargo.toml" --release --target aarch64-apple-ios

echo "🔨 Building for iOS simulator (arm64)..."
cargo build --manifest-path "$FFI_CRATE/Cargo.toml" --release --target aarch64-apple-ios-sim

echo "🔨 Building for iOS simulator (x86_64)..."
cargo build --manifest-path "$FFI_CRATE/Cargo.toml" --release --target x86_64-apple-ios

echo "🔨 Building for macOS (arm64)..."
cargo build --manifest-path "$FFI_CRATE/Cargo.toml" --release --target aarch64-apple-darwin

echo "🔨 Building for macOS (x86_64)..."
cargo build --manifest-path "$FFI_CRATE/Cargo.toml" --release --target x86_64-apple-darwin

# Create output directory
mkdir -p "$OUTPUT_DIR/lib"

# Create fat library for simulators (arm64 + x86_64)
echo ""
echo "📚 Creating fat library for simulators..."
lipo -create \
    "$PROJECT_ROOT/target/aarch64-apple-ios-sim/release/libprovekit_ffi.a" \
    "$PROJECT_ROOT/target/x86_64-apple-ios/release/libprovekit_ffi.a" \
    -output "$OUTPUT_DIR/lib/libprovekit_ffi-sim.a"

# Create fat library for macOS (arm64 + x86_64)
echo "📚 Creating fat library for macOS..."
lipo -create \
    "$PROJECT_ROOT/target/aarch64-apple-darwin/release/libprovekit_ffi.a" \
    "$PROJECT_ROOT/target/x86_64-apple-darwin/release/libprovekit_ffi.a" \
    -output "$OUTPUT_DIR/lib/libprovekit_ffi-macos.a"

# Remove existing XCFramework if present
rm -rf "$OUTPUT_DIR/ProveKitFFI.xcframework"

# Create XCFramework
echo "📦 Creating XCFramework..."
xcodebuild -create-xcframework \
    -library "$PROJECT_ROOT/target/aarch64-apple-ios/release/libprovekit_ffi.a" \
    -headers "$FFI_CRATE/include" \
    -library "$OUTPUT_DIR/lib/libprovekit_ffi-sim.a" \
    -headers "$FFI_CRATE/include" \
    -library "$OUTPUT_DIR/lib/libprovekit_ffi-macos.a" \
    -headers "$FFI_CRATE/include" \
    -output "$OUTPUT_DIR/ProveKitFFI.xcframework"

# Cleanup
rm -rf "$OUTPUT_DIR/lib"

echo ""
echo "✅ XCFramework created at:"
echo "   $OUTPUT_DIR/ProveKitFFI.xcframework"
echo ""
echo "To use in your iOS project:"
echo "  1. Add ProveKitSDK as a local Swift Package"
echo "  2. Import ProveKit in your Swift code"
