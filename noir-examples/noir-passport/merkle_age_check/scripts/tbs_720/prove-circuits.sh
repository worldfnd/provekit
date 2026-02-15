CIRCUITS=(
    "t_add_dsc_720"
    "t_add_id_data_720"
    "t_add_integrity_commit"
    "t_attest"
)  
LOG_DIR="../../benchmark-inputs/logs/prove/tbs_720"
mkdir -p "$LOG_DIR"

# Function to strip ANSI escape codes (works on macOS)
strip_ansi() {
    sed $'s/\x1b\[[0-9;]*m//g'
}

for circuit in "${CIRCUITS[@]}"; do
    echo "Proving $circuit"
    cargo run --release --bin provekit-cli prove ../../benchmark-inputs/$circuit-prover.pkp ../../benchmark-inputs/tbs_720/"$circuit".toml -o ../../benchmark-inputs/$circuit-proof.np 2>&1 | strip_ansi | tee "$LOG_DIR/$circuit.log"
    echo "Proved $circuit"
done
