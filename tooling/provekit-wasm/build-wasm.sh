#!/bin/bash
# Build WASM package with thread support via wasm-bindgen-rayon
#
# This script builds the WASM package with atomics and bulk-memory features
# enabled, which are required for wasm-bindgen-rayon's Web Worker-based
# parallelism.
#
# Requirements:
# - Nightly Rust toolchain (specified in rust-toolchain.toml)
# - wasm-pack: cargo install wasm-pack
# - Cross-Origin Isolation headers on the web server for SharedArrayBuffer

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."  # Go to workspace root

# Build flags for WASM threads
# Note: -reference-types disables newer WASM features that wasm-bindgen may not support
# Features enabled:
#   +atomics       - Required for SharedArrayBuffer/threading
#   +bulk-memory   - Required for wasm-bindgen-rayon
#   +mutable-globals - Required for threading
#   +simd128       - Enable WASM SIMD (128-bit vectors)
#   +relaxed-simd  - Enable relaxed SIMD operations (faster FMA, etc.)
#   -reference-types - Disable newer features wasm-bindgen may not support
# export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals,-reference-types'
export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128,+relaxed-simd,-reference-types'

# Increase max memory for wasm-bindgen threads (4GB = 65536 pages)
# Default is 16384 pages (1GB) which is not enough for large prover artifacts
export WASM_BINDGEN_THREADS_MAX_MEMORY=65536

# Target: web (required for wasm-bindgen-rayon)
# Note: nodejs target doesn't work with wasm-bindgen-rayon
TARGET="${1:-web}"

echo "Building WASM package with thread support..."
echo "  Target: $TARGET"
echo "  RUSTFLAGS: $RUSTFLAGS"
echo ""

# Use cargo directly with nightly toolchain and build-std
# wasm-pack doesn't handle -Z flags well, so we do it in two steps

# Step 1: Build with cargo (use nightly for build-std support)
cargo +nightly build \
    --release \
    --target wasm32-unknown-unknown \
    -p provekit-wasm \
    -Z build-std=panic_abort,std

# Step 2: Patch WASM binary to increase max memory from 1GB to 4GB
# Uses wasm-tools to properly parse and modify the memory section
WASM_FILE="target/wasm32-unknown-unknown/release/provekit_wasm.wasm"
echo ""
echo "Patching WASM binary for 4GB memory limit..."

# Check if wasm-tools is installed
if command -v wasm-tools &> /dev/null; then
    # Extract current memory config, update max pages, and reassemble
    # 65536 pages = 4GB (each page is 64KB)
    # Pattern handles both shared and non-shared memory imports
    wasm-tools print "$WASM_FILE" | \
        sed -E 's/\(memory \(;0;\) [0-9]+ [0-9]+( shared)?\)/(memory (;0;) 1024 65536\1)/' | \
        wasm-tools parse -o "$WASM_FILE"
    echo "  Memory limit patched to 65536 pages (4GB) using wasm-tools"
else
    echo "  WARNING: wasm-tools not found, skipping memory patching"
    echo "  Install with: cargo install wasm-tools"
    echo "  Memory will be limited to default (1GB)"
fi

# Step 3: Run wasm-bindgen to generate JS bindings
echo ""
echo "Running wasm-bindgen..."
wasm-bindgen \
    --target "$TARGET" \
    --out-dir tooling/provekit-wasm/pkg \
    "$WASM_FILE"

WASM_OUTPUT="tooling/provekit-wasm/pkg/provekit_wasm_bg.wasm"
echo ""
echo "⚡ Running wasm-opt optimization..."

if command -v wasm-opt &> /dev/null; then
    ORIGINAL_SIZE=$(stat -f%z "$WASM_OUTPUT" 2>/dev/null || stat -c%s "$WASM_OUTPUT")
    
    wasm-opt "$WASM_OUTPUT" \
        -O3 \
        --enable-simd \
        --enable-threads \
        --enable-bulk-memory \
        --enable-mutable-globals \
        --enable-nontrapping-float-to-int \
        --enable-sign-ext \
        --fast-math \
        --low-memory-unused \
        -o "$WASM_OUTPUT"
    
    NEW_SIZE=$(stat -f%z "$WASM_OUTPUT" 2>/dev/null || stat -c%s "$WASM_OUTPUT")
    SAVED=$((ORIGINAL_SIZE - NEW_SIZE))
    
    echo "  Original: $((ORIGINAL_SIZE / 1024 / 1024)) MB"
    echo "  Optimized: $((NEW_SIZE / 1024 / 1024)) MB"
    echo "  Saved: $((SAVED / 1024)) KB"
else
    echo "  WARNING: wasm-opt not found!"
    echo "  Install: npm install -g binaryen"
fi

echo ""
echo "Build complete! Package is in tooling/provekit-wasm/pkg"
echo ""
echo "Important: To use SharedArrayBuffer in the browser, you need these headers:"
echo "  Cross-Origin-Opener-Policy: same-origin"
echo "  Cross-Origin-Embedder-Policy: require-corp"
