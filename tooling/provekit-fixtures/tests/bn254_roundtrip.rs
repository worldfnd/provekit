//! bn254 prove→verify roundtrips over synthetic R1CS fixtures.

mod shared;

use provekit_backend_bn254::{register, Bn254Field};

roundtrip_suite!(Bn254Field, register);
