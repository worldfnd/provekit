//! bn254 field instantiation for the ProveKit spine.
//!
//! Holds the bn254-specific field primitives — the Skyscraper and Poseidon2
//! Merkle-hash engines / sponges and the custom NTT — and registers them, plus
//! a [`provekit_common::FieldHashProvider`], into the spine's global registries
//! via [`register`]. The spine (`provekit-common`) never names these directly;
//! it reaches them only through the registered provider.
//!
//! Call [`register`] once at startup before any prove/verify or public-input
//! hashing under the Skyscraper/Poseidon2 configurations.

pub mod ntt;
pub mod poseidon2;
pub mod skyscraper;

// Extern field primitive crates (the local `skyscraper`/`poseidon2` modules
// above shadow the crate names at this crate root, so reach the raw permutation
// helpers via the leading-`::` extern paths).
use ::poseidon2::poseidon2_hash;
use {
    ::skyscraper::simple::compress as skyscraper_compress,
    ark_ff::{BigInt, PrimeField},
    provekit_common::{
        field::{DynFieldSponge, FieldHashProvider},
        hash_config::PUBLIC_INPUTS_DST_FE,
        register_field_hash_provider, FieldElement, HashConfig,
    },
    std::sync::{Arc, Once},
    whir::engines::EngineId,
};

/// The bn254 field-native hash provider (see [`FieldHashProvider`]).
struct Bn254HashProvider;

impl FieldHashProvider for Bn254HashProvider {
    fn skyscraper_engine_id(&self) -> EngineId {
        skyscraper::SKYSCRAPER
    }

    fn poseidon2_engine_id(&self) -> EngineId {
        poseidon2::POSEIDON2
    }

    fn hash_skyscraper(&self, elements: &[FieldElement]) -> FieldElement {
        #[inline]
        fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
            let out = skyscraper_compress(l.into_bigint().0, r.into_bigint().0);
            FieldElement::new(BigInt(out))
        }

        let zero = FieldElement::from(0u64);
        match elements {
            [] => zero,
            [x] => compress(*x, zero),
            [first, rest @ ..] => rest.iter().copied().fold(*first, compress),
        }
    }

    fn hash_poseidon2(&self, elements: &[FieldElement]) -> FieldElement {
        let mut tagged = Vec::with_capacity(elements.len() + 1);
        tagged.push(*PUBLIC_INPUTS_DST_FE);
        tagged.extend_from_slice(elements);
        poseidon2_hash(&tagged)
    }

    fn field_sponge(&self, config: HashConfig) -> Box<dyn DynFieldSponge> {
        match config {
            HashConfig::Skyscraper => Box::new(skyscraper::SkyscraperSponge::default()),
            HashConfig::Poseidon2 => Box::new(poseidon2::Poseidon2Sponge::default()),
            other => {
                unreachable!("field_sponge is only valid for field-native configs, got {other:?}")
            }
        }
    }
}

static PROVIDER: Bn254HashProvider = Bn254HashProvider;

/// Register the bn254 field backend with the spine's global registries.
///
/// Registers the custom NTT engine ([`ntt::RSFr`]), the Skyscraper and
/// Poseidon2 Merkle-hash engines, and the field-native hash provider. Must be
/// called once before any prove/verify or public-input hashing. Idempotent.
pub fn register() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> = Arc::new(ntt::RSFr);
        whir::algebra::ntt::NTT.insert(ntt);

        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
        whir::hash::ENGINES.register(Arc::new(poseidon2::Poseidon2HashEngine));

        register_field_hash_provider(&PROVIDER);
    });
}
