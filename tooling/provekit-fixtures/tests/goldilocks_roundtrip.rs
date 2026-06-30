//! Goldilocks prove→verify roundtrips over synthetic R1CS fixtures.
//!
//! Base-compatible fixtures run on the canonical base-leaf `GoldilocksField`.
//! The challenge-bearing fixtures (LogUp, multi-challenge) place extension
//! challenge values in the witness, so they run on `GoldilocksEfField`, whose
//! base and extension fields coincide.
//!
//! TODO: run the challenge-bearing fixtures on the base-leaf field once a
//! base-field LogUp construction is available.

mod shared;

use provekit_backend_goldilocks::{register, GoldilocksEfField, GoldilocksField};

roundtrip_suite!(GoldilocksField, register);
challenge_roundtrip_suite!(GoldilocksEfField, register);
