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
export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals'

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
# The default max memory of 16384 pages (1GB) is baked into the binary
# We change it to 65536 pages (4GB) to support larger circuits
echo ""
echo "Patching WASM binary for 4GB memory limit..."
WASM_FILE="target/wasm32-unknown-unknown/release/provekit_wasm.wasm"
# 16384 in LEB128: 80 80 01, offset 0x1c2 from memory import
# Change byte at 0x1c2 from 01 to 04 (makes it 65536 = 4GB)
printf '\x04' | dd of="$WASM_FILE" bs=1 seek=$((0x1c2)) count=1 conv=notrunc 2>/dev/null
echo "  Memory limit patched: 16384 -> 65536 pages (1GB -> 4GB)"

# Step 3: Run wasm-bindgen to generate JS bindings
echo ""
echo "Running wasm-bindgen..."
wasm-bindgen \
    --target "$TARGET" \
    --out-dir tooling/provekit-wasm/pkg \
    "$WASM_FILE"

echo ""
echo "Build complete! Package is in tooling/provekit-wasm/pkg"
echo ""
echo "Important: To use SharedArrayBuffer in the browser, you need these headers:"
echo "  Cross-Origin-Opener-Policy: same-origin"
echo "  Cross-Origin-Embedder-Policy: require-corp"
