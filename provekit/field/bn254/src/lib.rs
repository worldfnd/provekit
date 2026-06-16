//! bn254 field backend for the ProveKit spine.
//!
//! [`register`] installs the Skyscraper and Poseidon2 Merkle-hash engines, the
//! custom NTT, and a [`provekit_common::FieldHashProvider`]. Call it once at
//! startup before any prove/verify or public-input hashing.

pub mod bigint_mod;
pub mod ec_arith;
pub mod ntt;
pub mod poseidon2;
pub mod skyscraper;
pub mod witness;

// The local `skyscraper`/`poseidon2` modules shadow the crate names here, so
// reach the extern crates via leading-`::` paths.
use {
    ::poseidon2::poseidon2_hash,
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

/// Register the bn254 field backend (NTT engine, Skyscraper/Poseidon2 Merkle
/// engines, and the hash provider). Idempotent.
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
