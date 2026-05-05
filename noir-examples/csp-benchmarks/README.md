# Ethproofs client-side proving benchmark circuits

Noir examples for the hash and signature targets listed on
[Ethproofs CSP benchmarks](https://ethproofs.org/csp-benchmarks). The
sizes mirror the benchmark metadata in
[`privacy-ethereum/csp-benchmarks`](https://github.com/privacy-ethereum/csp-benchmarks).

| Target | Cases | Implementation note |
| --- | --- | --- |
| SHA-256 | 128, 256, 512, 1024, 2048 bytes | Uses `noir-lang/sha256::sha256_var`, which lowers compression through Noir's SHA-256 blackbox. |
| Keccak-256 | 128, 256, 512, 1024, 2048 bytes | Uses the native Noir Keccak circuit from this benchmark suite with a witness-focused u32 lane representation; ProveKit does not lower Noir's Keccak blackbox for these cases. |
| Poseidon | 2, 4, 8, 12, 16 field elements | Uses `noir-lang/poseidon` BN254 native Noir helpers. |
| Poseidon2 | 2, 4, 8, 12, 16 field elements | Uses native `TaceoLabs/noir-poseidon` for states 2, 8, 12, and 16; state 4 intentionally uses Noir's Poseidon2 permutation blackbox via `noir-lang/poseidon`. |
| ECDSA | secp256r1 over a 32-byte digest | Uses `zkpassport/noir-ecdsa` native P-256 verification (with `noir_bigcurve`/`noir-bignum` arithmetic) because ProveKit does not lower Noir's ECDSA blackbox yet. |
