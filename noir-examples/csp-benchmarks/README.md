# Ethproofs client-side proving benchmark circuits

Noir examples for the hash and signature targets listed on
[Ethproofs CSP benchmarks](https://ethproofs.org/csp-benchmarks). The
sizes mirror the benchmark metadata in
[`privacy-ethereum/csp-benchmarks`](https://github.com/privacy-ethereum/csp-benchmarks).

| Target | Cases | Implementation note |
| --- | --- | --- |
| SHA-256 | 128, 256, 512, 1024, 2048 bytes | Uses `noir-lang/sha256::sha256_var`, which lowers compression through Noir's SHA-256 blackbox. |
| Keccak-256 | 128, 256, 512, 1024, 2048 bytes | Uses the Ethproofs Noir Keccak circuit because this repo does not lower Noir's Keccak blackbox to R1CS. |
| Poseidon | 2, 4, 8, 12, 16 field elements | Uses `noir-lang/poseidon` BN254 helpers. |
| Poseidon2 | 2, 4, 8, 12, 16 field elements | Uses the stdlib Poseidon2 blackbox for the 4-field state and `TaceoLabs/noir-poseidon` for the other benchmark arities. |
| ECDSA | secp256r1 over a 32-byte digest | Uses `noir_bigcurve` P-256 verification logic. |

The 4-field Poseidon2 fixture is the only stdlib blackbox Poseidon2 case here
because Noir's current blackbox solver accepts 4-field Poseidon2 states. The
other CSP Poseidon2 arities remain explicit Noir hash circuits so the full
Ethproofs target matrix is still covered by ProveKit tests.
