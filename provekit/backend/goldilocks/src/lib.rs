//! Goldilocks instantiation of the ProveKit spine: the `Field64_3` proof field,
//! its hash glue, and the engine registration needed to prove and verify.

mod bytes;
mod field;
mod field_hash;
mod transcript_sponge;

pub use {field::GoldilocksField, transcript_sponge::TranscriptSponge};

/// Register the Goldilocks engines in whir's global registries.
///
/// Must be called once before any prove/verify operation. Idempotent — safe to
/// call multiple times.
pub fn register() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<whir::algebra::fields::Field64_3>> =
            Arc::new(whir::algebra::ntt::NttEngine::<
                whir::algebra::fields::Field64_3,
            >::new_from_fftfield());
        whir::algebra::ntt::NTT.insert(ntt);
    });
}
