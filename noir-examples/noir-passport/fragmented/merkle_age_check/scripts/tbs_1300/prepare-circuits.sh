CIRCUITS=(
    "t_add_dsc_hash_1300"
    "t_add_dsc_verify_1300"
    "t_add_id_data_1300"
    "t_add_integrity_commit"
    "t_attest"
)  
LOG_DIR="../../benchmark-inputs/logs/prepare/tbs_1300"
mkdir -p "$LOG_DIR"

# Function to strip ANSI escape codes (works on macOS)
strip_ansi() {
    sed $'s/\x1b\[[0-9;]*m//g'
}

for circuit in "${CIRCUITS[@]}"; do
    echo "Preparing $circuit"
    cargo run --release --bin provekit-cli prepare ../../target/$circuit.json --pkp ../../benchmark-inputs/$circuit-prover.pkp --pkv ../../benchmark-inputs/$circuit-verifier.pkv 2>&1 | strip_ansi | tee "$LOG_DIR/$circuit.log"
    echo "Prepared $circuit"
done
