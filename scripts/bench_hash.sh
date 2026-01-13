#!/bin/bash

echo "Benchmarking hash functions in the age check circuit...\n"

CIRCUIT_DIR="noir-examples/noir-passport-examples/complete_age_check"

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

echo "Prepare the Noir program"
# Prepare the Noir program (generates prover and verifier files):
# cargo run --release --bin provekit-cli prepare \
#   $CIRCUIT_DIR/target/complete_age_check.json \
#   --pkp $CIRCUIT_DIR/prover.pkp \
#   --pkv $CIRCUIT_DIR/verifier.pkv \
#   --hash "sha2"
  
  # 2>&1 | format_benchmark_table
echo "\n"


# ./target/release/provekit-cli prepare \
#   $CIRCUIT_DIR/target/complete_age_check.json \
#   --pkp $CIRCUIT_DIR/prover.pkp \
#   --pkv $CIRCUIT_DIR/verifier.pkv
# echo "\n"


# echo "Generate proof"
# Generate the Noir Proof using the input Toml file

# cargo run --release --bin provekit-cli prove $CIRCUIT_DIR/prover.pkp $CIRCUIT_DIR/Prover.toml -o $CIRCUIT_DIR/proof.np

# 2>&1 | format_benchmark_table
echo "\n"

# echo "Verify proof"
# Verify the Noir Proof
cargo run --release --bin provekit-cli verify $CIRCUIT_DIR/verifier.pkv $CIRCUIT_DIR/proof.np
#  2>&1 | format_benchmark_table
echo "\n"


# Run each benchmark multiple times
# hyperfine --warmup 1 \
#     --show-output \
#     --runs 2 \
#     "cargo run --release --bin provekit-cli prove $CIRCUIT_DIR/prover.pkp $CIRCUIT_DIR/Prover.toml -o $CIRCUIT_DIR/proof.np 2>&1 | format_benchmark_table"


# Only generates time
# Sampling profiler
# samply record -r 10000 -- cargo run --release --bin provekit-cli prove $CIRCUIT_DIR/prover.pkp $CIRCUIT_DIR/Prover.toml -o $CIRCUIT_DIR/proof.np
# samply record -r 10000 -- cargo run --release --bin provekit-cli verify $CIRCUIT_DIR/verifier.pkv $CIRCUIT_DIR/proof.np

echo "Benchmarking completed."