//! Goldilocks prove→verify roundtrips over synthetic R1CS fixtures.
//!
//! Base-compatible fixtures run on the canonical base-leaf `GoldilocksField`
//! (the BF×EF split). The challenge-bearing fixtures (LogUp, multi-challenge)
//! place ext challenge values in the witness, so they run on the temporary
//! `GoldilocksEfField` (`Identity`) until the k-base LogUp construction (T12).

mod shared;

use provekit_backend_goldilocks::{register, GoldilocksEfField, GoldilocksField};

roundtrip_suite!(GoldilocksField, register);
challenge_roundtrip_suite!(GoldilocksEfField, register);
