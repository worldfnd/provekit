#!/bin/bash
# Benchmark ProveKit with different hash functions
# Requires: hyperfine (brew install hyperfine)

set -e

CIRCUIT="noir-examples/noir-passport-examples/complete_age_check"
CIRCUIT_JSON="$CIRCUIT/target/complete_age_check.json"
PROVER_TOML="$CIRCUIT/Prover.toml"
CLI="./target/release/provekit-cli"
BENCH_DIR="/tmp/provekit-bench"

echo "=========================================="
echo "ProveKit Hash Function Benchmark"
echo "Circuit: complete_age_check"
echo "=========================================="

# Check dependencies
if ! command -v hyperfine &> /dev/null; then
    echo "Error: hyperfine not found. Install with: brew install hyperfine"
    exit 1
fi

# Build release binary
echo ""
echo "Building release binary..."
cargo build --release -p provekit-cli --quiet

# Create benchmark directory
mkdir -p $BENCH_DIR

# Prepare for each hash function
echo ""
echo "=========================================="
echo "Preparing circuits for each hash function"
echo "=========================================="

for HASH in skyscraper sha2 sha3 blake3; do
    echo "Preparing $HASH..."
    $CLI prepare $CIRCUIT_JSON \
        --pkp $BENCH_DIR/$HASH.pkp \
        --pkv $BENCH_DIR/$HASH.pkv \
        --hash $HASH 2>&1 | grep -E "(INFO|duration)" | tail -1
done

# Benchmark proving
echo ""
echo "=========================================="
echo "Benchmarking PROVE (5 runs each)"
echo "=========================================="

hyperfine \
    --warmup 1 \
    --runs 5 \
    --export-markdown $BENCH_DIR/prove_results.md \
    --export-json $BENCH_DIR/prove_results.json \
    --command-name "skyscraper" "$CLI prove $BENCH_DIR/skyscraper.pkp $PROVER_TOML -o $BENCH_DIR/sky.np 2>/dev/null" \
    --command-name "sha2" "$CLI prove $BENCH_DIR/sha2.pkp $PROVER_TOML -o $BENCH_DIR/sha2.np 2>/dev/null" \
    --command-name "sha3" "$CLI prove $BENCH_DIR/sha3.pkp $PROVER_TOML -o $BENCH_DIR/sha3.np 2>/dev/null" \
    --command-name "blake3" "$CLI prove $BENCH_DIR/blake3.pkp $PROVER_TOML -o $BENCH_DIR/blake3.np 2>/dev/null"

# Benchmark verification
echo ""
echo "=========================================="
echo "Benchmarking VERIFY (10 runs each)"
echo "=========================================="

hyperfine \
    --warmup 2 \
    --runs 10 \
    --export-markdown $BENCH_DIR/verify_results.md \
    --export-json $BENCH_DIR/verify_results.json \
    --command-name "skyscraper" "$CLI verify $BENCH_DIR/skyscraper.pkv $BENCH_DIR/sky.np 2>/dev/null" \
    --command-name "sha2" "$CLI verify $BENCH_DIR/sha2.pkv $BENCH_DIR/sha2.np 2>/dev/null" \
    --command-name "sha3" "$CLI verify $BENCH_DIR/sha3.pkv $BENCH_DIR/sha3.np 2>/dev/null" \
    --command-name "blake3" "$CLI verify $BENCH_DIR/blake3.pkv $BENCH_DIR/blake3.np 2>/dev/null"

# Print proof sizes
echo ""
echo "=========================================="
echo "Proof Sizes"
echo "=========================================="
ls -lh $BENCH_DIR/*.np | awk '{print $9, $5}'

# Print results location
echo ""
echo "=========================================="
echo "Results saved to:"
echo "  - $BENCH_DIR/prove_results.md"
echo "  - $BENCH_DIR/verify_results.md"
echo "  - $BENCH_DIR/prove_results.json"
echo "  - $BENCH_DIR/verify_results.json"
echo "=========================================="
