CIRCUITS=(
    "t_add_dsc_720"
    "t_add_id_data_720"
    "t_add_integrity_commit"
    "t_attest"
)

for circuit in "${CIRCUITS[@]}"; do
    echo "=== $circuit ==="
    cargo run --release --bin provekit-cli show-inputs ../../benchmark-inputs/$circuit-verifier.pkv ../../benchmark-inputs/$circuit-proof.np
    echo ""
done
