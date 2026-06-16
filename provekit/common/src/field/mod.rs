//! Field-specific proof operations abstracted behind a trait.
//!
//! [`ProofField`] carries the per-field glue that the WHIR spine needs but the
//! upstream `whir::algebra::Embedding` trait does not provide: engine/NTT
//! registration, the field-native Merkle-hash engine ids, the public-input
//! binding hashes, and the field-native Fiat-Shamir sponge constructor.
//!
//! For PR A it is implemented only for the bn254 scalar field
//! ([`crate::FieldElement`]). The spine reaches every field-specific symbol
//! through this surface, so the concrete implementation can later move into a
//! standalone `field/bn254` crate without the spine naming `skyscraper`,
//! `poseidon2`, or `ntt` directly.

use {
    crate::{hash_config::PUBLIC_INPUTS_DST_FE, FieldElement, HashConfig},
    spongefish::DuplexSpongeInterface,
    whir::engines::EngineId,
};

/// Object-safe Fiat-Shamir sponge for the field-native hash configurations
/// ([`HashConfig::Skyscraper`], [`HashConfig::Poseidon2`]).
///
/// `spongefish::DuplexSpongeInterface` is not object-safe — its methods return
/// `&mut Self` — so the runtime [`crate::TranscriptSponge`] cannot hold a
/// `Box<dyn DuplexSpongeInterface>`. This object-safe shim (methods return
/// `()`, plus an explicit `clone_box`) lets the spine keep `TranscriptSponge`
/// in `common` while the concrete field-native sponges live in the field crate.
pub trait DynFieldSponge: Send {
    /// Absorb bytes into the sponge.
    fn absorb(&mut self, input: &[u8]);
    /// Squeeze bytes out of the sponge.
    fn squeeze(&mut self, output: &mut [u8]);
    /// Ratchet the sponge state.
    fn ratchet(&mut self);
    /// Clone into a fresh box (enables `#[derive(Clone)]` on the holder).
    fn clone_box(&self) -> Box<dyn DynFieldSponge>;
}

/// Any `spongefish` byte-sponge that is `Clone` is automatically a
/// [`DynFieldSponge`]. This blanket impl is field-agnostic and stays in
/// `common`; only the *construction* of the concrete sponges (in
/// [`ProofField::field_sponge`]) is field-specific.
impl<S> DynFieldSponge for S
where
    S: DuplexSpongeInterface<U = u8> + Clone + Send + 'static,
{
    fn absorb(&mut self, input: &[u8]) {
        DuplexSpongeInterface::absorb(self, input);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        DuplexSpongeInterface::squeeze(self, output);
    }

    fn ratchet(&mut self) {
        DuplexSpongeInterface::ratchet(self);
    }

    fn clone_box(&self) -> Box<dyn DynFieldSponge> {
        Box::new(self.clone())
    }
}

/// Per-field glue required by the WHIR spine.
///
/// Implemented for [`crate::FieldElement`] (bn254 scalar field) in PR A. Every
/// method abstracts a reference that would otherwise tie the spine to the
/// `skyscraper`, `poseidon2`, or `ntt` crates.
pub trait ProofField: Sized {
    /// Register this field's custom WHIR engines (NTT + Merkle hash engines).
    ///
    /// Idempotency is the caller's concern (see [`crate::register_ntt`]).
    fn register_engines();

    /// WHIR engine id for the field-native Skyscraper Merkle hash.
    fn skyscraper_engine_id() -> EngineId;

    /// WHIR engine id for the field-native Poseidon2 Merkle hash.
    fn poseidon2_engine_id() -> EngineId;

    /// Skyscraper public-input binding hash (pairwise compression; empty input
    /// hashes to 0; not domain-separated — see [`crate::hash_config`]).
    fn hash_skyscraper(elements: &[Self]) -> Self;

    /// Poseidon2 public-input binding hash (DST-tagged one-shot).
    fn hash_poseidon2(elements: &[Self]) -> Self;

    /// Construct the field-native Fiat-Shamir sponge for `config`.
    ///
    /// Only called for [`HashConfig::Skyscraper`] and [`HashConfig::Poseidon2`];
    /// the byte-sponge configurations are handled directly by
    /// [`crate::TranscriptSponge`].
    fn field_sponge(config: HashConfig) -> Box<dyn DynFieldSponge>;
}

impl ProofField for FieldElement {
    fn register_engines() {
        use std::sync::Arc;

        // Register NTT for polynomial operations.
        #[cfg(not(feature = "provekit_ntt"))]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(whir::algebra::ntt::NttEngine::<FieldElement>::new_from_fftfield());

        #[cfg(feature = "provekit_ntt")]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(crate::ntt::RSFr);

        whir::algebra::ntt::NTT.insert(ntt);

        // Register ProveKit-specific engines; WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES.register(Arc::new(crate::skyscraper::SkyscraperHashEngine));
        whir::hash::ENGINES.register(Arc::new(crate::poseidon2::Poseidon2HashEngine));
    }

    fn skyscraper_engine_id() -> EngineId {
        crate::skyscraper::SKYSCRAPER
    }

    fn poseidon2_engine_id() -> EngineId {
        crate::poseidon2::POSEIDON2
    }

    fn hash_skyscraper(elements: &[Self]) -> Self {
        use ark_ff::{BigInt, PrimeField};

        #[inline]
        fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
            let out = skyscraper::simple::compress(l.into_bigint().0, r.into_bigint().0);
            FieldElement::new(BigInt(out))
        }

        let zero = FieldElement::from(0u64);
        match elements {
            [] => zero,
            [x] => compress(*x, zero),
            [first, rest @ ..] => rest.iter().copied().fold(*first, compress),
        }
    }

    fn hash_poseidon2(elements: &[Self]) -> Self {
        let mut tagged = Vec::with_capacity(elements.len() + 1);
        tagged.push(*PUBLIC_INPUTS_DST_FE);
        tagged.extend_from_slice(elements);
        poseidon2::poseidon2_hash(&tagged)
    }

    fn field_sponge(config: HashConfig) -> Box<dyn DynFieldSponge> {
        match config {
            HashConfig::Skyscraper => Box::new(crate::skyscraper::SkyscraperSponge::default()),
            HashConfig::Poseidon2 => Box::new(crate::poseidon2::Poseidon2Sponge::default()),
            other => unreachable!("field_sponge is only valid for field-native configs, got {other:?}"),
        }
    }
}
