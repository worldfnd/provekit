# Ethproofs client-side proving benchmark circuits

Noir versions of the benchmark targets listed on [Ethproofs CSP benchmarks](https://ethproofs.org/csp-benchmarks): SHA-256, Keccak, Poseidon, Poseidon2, and ECDSA.

Benchmark target sizes mirror [`privacy-ethereum/csp-benchmarks`](https://github.com/privacy-ethereum/csp-benchmarks) metadata:

- SHA-256 / Keccak byte inputs: 128, 256, 512, 1024, 2048 bytes
- Poseidon / Poseidon2 field inputs: 2, 4, 8, 12, 16 field elements
- ECDSA: secp256r1 verification over a 32-byte digest

The SHA-256 wrappers use the `noir-lang/sha256` package, which routes compression through Noir's SHA-256 blackbox. The `poseidon2_4` wrapper uses `std::hash::poseidon2_permutation` so ProveKit exercises its Poseidon2 blackbox path where Noir's current blackbox solver supports it; the other Poseidon2 arities use the `TaceoLabs/noir-poseidon` hash helpers. The Keccak implementation remains vendored from the Ethproofs CSP benchmark circuit because ProveKit does not currently lower Noir's Keccak blackbox into R1CS.
