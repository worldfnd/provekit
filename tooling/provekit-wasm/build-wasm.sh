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
# Target features:
#   +atomics         - Required for SharedArrayBuffer/threading
#   +bulk-memory     - Required for wasm-bindgen-rayon
#   +mutable-globals - Required for threading
#   +simd128         - Enable WASM SIMD (128-bit vectors)
#   +relaxed-simd    - Enable relaxed SIMD operations (faster FMA, etc.)
#   -reference-types - Disable reference-types (wasm-bindgen compat)
# Linker flags for shared memory (required for multi-threaded WASM):
#   --shared-memory  - Emit shared memory attribute
#   --import-memory  - Import memory (so main thread provides SharedArrayBuffer)
#   --max-memory     - Required for shared memory (4GB = WASM max)
#   --export=__wasm_init_tls,__tls_size,__tls_align,__tls_base
#                    - Export TLS symbols required by wasm-bindgen for threading
export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128,+relaxed-simd,-reference-types -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'

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
cargo +nightly-2026-03-04 build \
    --release \
    --target wasm32-unknown-unknown \
    -p provekit-wasm \
    -Z build-std=panic_abort,std

# Step 2: Run wasm-bindgen to generate JS bindings
WASM_FILE="target/wasm32-unknown-unknown/release/provekit_wasm.wasm"
echo ""
echo "Running wasm-bindgen..."
wasm-bindgen \
    --target "$TARGET" \
    --out-dir tooling/provekit-wasm/pkg \
    "$WASM_FILE"

WASM_OUTPUT="tooling/provekit-wasm/pkg/provekit_wasm_bg.wasm"

# Step 3: Optimize with wasm-opt
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
