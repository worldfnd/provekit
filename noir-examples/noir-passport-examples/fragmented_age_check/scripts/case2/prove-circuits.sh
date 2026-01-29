CIRCUITS=(
    "sig_check_dsc_1300_hash"
    "sig_check_dsc_1300_verify"
    "sig_check_id_data_1300"
    "data_check_integrity_sa"
    "compare_age"
)  
LOG_DIR="../../benchmark-inputs/logs/prove/case2"
mkdir -p "$LOG_DIR"

# Function to strip ANSI escape codes (works on macOS)
strip_ansi() {
    sed $'s/\x1b\[[0-9;]*m//g'
}

for circuit in "${CIRCUITS[@]}"; do
    echo "Proving $circuit"
    cargo run --release --bin provekit-cli prove ../../benchmark-inputs/$circuit-prover.pkp ../../benchmark-inputs/case2/"$circuit"_prover.toml -o ../../benchmark-inputs/$circuit-proof.np 2>&1 | strip_ansi | tee "$LOG_DIR/$circuit.log"
    echo "Proved $circuit"
done
