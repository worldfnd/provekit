//! BN254 instantiation of the ProveKit spine (`Identity<Fr>`, base == ext),
//! plus the bn254-welded Noir/Mavros frontend. Organized into `scheme` (the
//! serialized PKP/PKV/proof types), `frontend` (the Noir/ACIR bridge),
//! `solver` (witness solving), and the `prove`/`verify` orchestration.

mod bytes;
mod compress;
mod field;
mod field_hash;
mod frontend;
#[cfg(not(target_arch = "wasm32"))]
mod mavros_prove;
mod ntt;
mod poseidon2;
mod prove;
mod scheme;
mod skyscraper;
mod solver;
mod transcript_sponge;
mod verify;
#[cfg(target_arch = "wasm32")]
mod wasm_mavros_prove;
pub mod witness;

#[cfg(target_arch = "wasm32")]
pub use wasm_mavros_prove::{
    prove_mavros_with_wasm_driver, MavrosPhase1Result, MavrosTableInfo, MavrosWasmDriver,
};
pub use {
    acir::FieldElement as NoirElement,
    ark_bn254::Fr as FieldElement,
    compress::CompressedLayers,
    field::{Bn254Field, WhirConfig, WhirZkConfig},
    frontend::{noir_to_native, NoirWitnessGenerator, PrintAbi},
    ntt::RSFr,
    prove::Prove,
    provekit_common::{ec_arith::ec_scalar_mul, ProvekitProof},
    scheme::{
        ConstraintsLayout, MavrosProver, MavrosSchemeData, NoirProofScheme, NoirProver,
        NoirSchemeData, Prover, Verifier, WitnessLayout,
    },
    skyscraper::SkyscraperPoW,
    solver::solve_witness_vec,
    transcript_sponge::TranscriptSponge,
    verify::Verify,
};

/// Register the bn254 ProveKit engines in whir's global registries.
///
/// Must be called once before any prove/verify operation. Idempotent — safe to
/// call multiple times.
pub fn register() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Register NTT for polynomial operations
        #[cfg(not(feature = "provekit_ntt"))]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(whir::algebra::ntt::NttEngine::<FieldElement>::new_from_fftfield());

        #[cfg(feature = "provekit_ntt")]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(crate::ntt::RSFr);

        whir::algebra::ntt::NTT.insert(ntt);

        // Register ProveKit-specific engines; WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
        whir::hash::ENGINES.register(Arc::new(poseidon2::Poseidon2HashEngine));
    });
}
