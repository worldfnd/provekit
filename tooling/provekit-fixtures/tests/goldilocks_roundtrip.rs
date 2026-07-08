//! Goldilocks prove→verify roundtrips over synthetic R1CS fixtures.

mod shared;

use provekit_backend_goldilocks::{register, GoldilocksField};

roundtrip_suite!(GoldilocksField, register);
