CIRCUITS=(
    "t_add_dsc_hash_1300"
    "t_add_dsc_verify_1300"
    "t_add_id_data_1300"
    "t_add_integrity_commit"
    "t_attest"
)

for circuit in "${CIRCUITS[@]}"; do
    echo "=== $circuit ==="
    cargo run --release --bin provekit-cli show-inputs ../../benchmark-inputs/$circuit-verifier.pkv ../../benchmark-inputs/$circuit-proof.np
    echo ""
done
