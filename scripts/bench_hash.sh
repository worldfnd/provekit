#!/bin/bash

echo "Benchmarking hash functions in the age check circuit...\n"

# Configuration
CIRCUIT_DIR="noir-examples/noir-passport-examples/complete_age_check"
CIRCUIT_JSON="$CIRCUIT_DIR/target/complete_age_check.json"
HASH_FUNCTIONS=("skyscraper" "sha2" "sha3", "blake3")
RUN="./target/release/provekit-cli"


# Compile the Noir circuit. Setup once.
# cd $CIRCUIT_DIR
# nargo compile

format_benchmark_table() {
  awk -F, '
  /run:/ {
      # Extracting values based on your specific log structure
      split($1, d_parts, " "); d = d_parts[3];
      split($2, m_parts, " "); m = m_parts[1] " " m_parts[2];
      split($3, l_parts, " "); l = l_parts[1] " " l_parts[2];
      split($4, c_parts, " "); c = c_parts[1] " " c_parts[2];
      split($5, a_parts, " "); a = a_parts[1];
  }
  END {
      print "--------------------------------------------------"
      printf "%-19s | %s\n", "Metric", "Value"
      print "--------------------|-----------------------------"
      printf "%-19s | %s\n", "Total Duration", (d ? d : "N/A")
      printf "%-19s | %s\n", "Peak Memory (RSS)", (m ? m : "N/A")
      printf "%-19s | %s\n", "Local Memory", (l ? l : "N/A")
      printf "%-19s | %s\n", "Current Memory", (c ? c : "N/A")
      printf "%-19s | %s\n", "Total Allocations", (a ? a : "N/A")
      print "--------------------------------------------------"
  }'
}

export -f format_benchmark_table

# Build the provekit-cli binary
# echo "Building provekit-cli..."
# # cargo build --release -p provekit-cli 2>&1
# echo "\n"


# # --- Color Definitions ---
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Header ---
echo "${BOLD}==========================================================${NC}"
echo "${BOLD}           PROVEKIT BENCHMARK SUITE                       ${NC}"
echo "${BOLD}==========================================================${NC}"

echo "Single Run Benchmarks for Different Hash Functions:\n"


for HASH in "${HASH_FUNCTIONS[@]}"; do
    echo "\n${YELLOW}▶ Testing Hash Strategy:${NC} ${BOLD}${HASH}${NC}"

    # 1. PREPARE STAGE
    echo "${BOLD}[1/3]${NC} Generating Prover/Verifier artifacts... "
    PREPARE_OUT=$($RUN prepare \
      $CIRCUIT_JSON\
      --pkp "$CIRCUIT_DIR/$HASH.pkp" \
      --pkv "$CIRCUIT_DIR/$HASH.pkv" \
      --hash "$HASH" 2>&1)
    echo "$PREPARE_OUT" | format_benchmark_table

    # 2. PROVE STAGE
    echo "\n${BOLD}[2/3]${NC} Executing ZK-Proof Generation..."
    $RUN prove \
      "$CIRCUIT_DIR/$HASH.pkp" \
      "$CIRCUIT_DIR/Prover.toml" \
      -o "$CIRCUIT_DIR/$HASH.np" 2>&1 | format_benchmark_table

    # 3. VERIFY STAGE
    echo "\n${BOLD}[3/3]${NC} Validating Proof Integrity..."
    $RUN verify \
      "$CIRCUIT_DIR/$HASH.pkv" \
      "$CIRCUIT_DIR/$HASH.np" 2>&1 | format_benchmark_table

done

echo "\n${BOLD}==========================================================${NC}"
# Multi runs with hyperfine
echo "Multi Run Benchmarks for Different Hash Functions with hyperfine:\n"
echo "\n${BOLD}==========================================================${NC}"


echo "\n${BOLD}${YELLOW}⚒  STAGE 1: Artifact Preparation (PKP/PKV Generation)${NC}"

HYPERFINE_ARGS_PREPARE=(
    hyperfine
    --warmup 0
    --runs 1
)
for HASH in "${HASH_FUNCTIONS[@]}"; do
    HYPERFINE_ARGS_PREPARE+=(--command-name "$HASH")
    HYPERFINE_ARGS_PREPARE+=("$RUN prepare \
        $CIRCUIT_JSON \
        --pkp "$CIRCUIT_DIR/$HASH.pkp" \
        --pkv "$CIRCUIT_DIR/$HASH.pkv" \
        --hash $HASH")
done
"${HYPERFINE_ARGS_PREPARE[@]}"


echo "\n${BOLD}${CYAN}🚀 STAGE 2: Proving Performance 5 Runs ${NC}"


HYPERFINE_ARGS_PROVE=(
    hyperfine
    --warmup 1
    --runs 5
)
for HASH in "${HASH_FUNCTIONS[@]}"; do
    HYPERFINE_ARGS_PROVE+=(--command-name "$HASH")
    HYPERFINE_ARGS_PROVE+=("$RUN prove \
        $CIRCUIT_DIR/$HASH.pkp \
        $CIRCUIT_DIR/Prover.toml \
        -o $CIRCUIT_DIR/$HASH.np")
done
"${HYPERFINE_ARGS_PROVE[@]}"

echo "\n${BOLD}${GREEN}⚖  STAGE 3: Verification Speed 5 Runs ${NC}"

# Initialize the hyperfine prover command array
HYPERFINE_ARGS_VERIFY=(
    hyperfine
    --warmup 1
    --runs 5
)
for HASH in "${HASH_FUNCTIONS[@]}"; do
    HYPERFINE_ARGS_VERIFY+=(--command-name "$HASH")
    HYPERFINE_ARGS_VERIFY+=("$RUN verify \
        $CIRCUIT_DIR/$HASH.pkv \
        $CIRCUIT_DIR/$HASH.np")
done

"${HYPERFINE_ARGS_VERIFY[@]}"




# Only generates time
# Sampling profiler
# samply record -r 10000 -- cargo run --release --bin provekit-cli prove $CIRCUIT_DIR/prover.pkp $CIRCUIT_DIR/Prover.toml -o $CIRCUIT_DIR/proof.np
# samply record -r 10000 -- cargo run --release --bin provekit-cli verify $CIRCUIT_DIR/verifier.pkv $CIRCUIT_DIR/proof.np