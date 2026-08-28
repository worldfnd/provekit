# Native Circom WebAuthn adapter

This package wraps the pinned `privacy-ethereum/webauth-circom` fixture with
the native Rapidsnark backend. Its witness and prover phases are recorded in
the canonical input-to-proof boundary, with proof verification and tamper
rejection as mandatory gates.

The E15 32-bit cold lane is retained as a structured OOM gap when the zkey and
WTNS cannot be mapped. It is never replaced with a browser or iPhone timing.
