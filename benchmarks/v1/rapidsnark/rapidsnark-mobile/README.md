# Native Rapidsnark adapter

This crate is the shared native Groth16 wrapper used by the canonical iPhone
and E15 Circom lanes. It consumes frozen Circom WTNS inputs and standard zkeys,
and exposes witness, prove, verify, tamper, and input-to-proof Mobench
functions. Passport registration and disclosure are separate product stages;
Passport P1 is a distinct monolithic profile.

Builds are driven by the scripts in `../scripts/` and the exact adapter/prover
versions in `../toolchains.lock.json`. Generated mobile packages and raw
BrowserStack evidence stay under `target/v1-benchmarks/`.
