//! Field-specific proof operations behind a registered provider.
//!
//! `common` names no concrete field. A field crate (e.g.
//! `provekit-field-bn254`) registers a [`FieldHashProvider`] via
//! [`register_field_hash_provider`], and the spine looks it up at runtime, like
//! whir's `ENGINES`/`NTT` registries.

use {
    crate::{FieldElement, HashConfig},
    spongefish::DuplexSpongeInterface,
    std::sync::OnceLock,
    whir::engines::EngineId,
};

/// Object-safe Fiat-Shamir sponge for the field-native hash configs.
///
/// Lets `TranscriptSponge` box a field-native sponge: `spongefish`'s
/// `DuplexSpongeInterface` returns `&mut Self`, so it is not object-safe.
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

/// Any `Clone` byte-sponge from `spongefish` is automatically a
/// `DynFieldSponge`.
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

/// Field-native Merkle engine ids, public-input binding hashes, and the
/// Fiat-Shamir sponge constructor. Implemented and registered by a field crate.
pub trait FieldHashProvider: Send + Sync {
    /// WHIR engine id for the field-native Skyscraper Merkle hash.
    fn skyscraper_engine_id(&self) -> EngineId;

    /// WHIR engine id for the field-native Poseidon2 Merkle hash.
    fn poseidon2_engine_id(&self) -> EngineId;

    /// Skyscraper public-input binding hash (pairwise compression; empty input
    /// hashes to 0; not domain-separated — see [`crate::hash_config`]).
    fn hash_skyscraper(&self, elements: &[FieldElement]) -> FieldElement;

    /// Poseidon2 public-input binding hash (DST-tagged one-shot).
    fn hash_poseidon2(&self, elements: &[FieldElement]) -> FieldElement;

    /// Construct the field-native Fiat-Shamir sponge for `config` (only called
    /// for [`HashConfig::Skyscraper`] and [`HashConfig::Poseidon2`]).
    fn field_sponge(&self, config: HashConfig) -> Box<dyn DynFieldSponge>;
}

static FIELD_HASH_PROVIDER: OnceLock<&'static dyn FieldHashProvider> = OnceLock::new();

/// Register the field-native hash provider, called once at startup by the field
/// crate's `register()`. The first registrant wins; a later call (even with a
/// different provider) is ignored, so a binary must register exactly one field
/// crate.
pub fn register_field_hash_provider(provider: &'static dyn FieldHashProvider) {
    let _ = FIELD_HASH_PROVIDER.set(provider);
}

/// Access the registered field-native hash provider.
///
/// # Panics
/// Panics if no provider has been registered. Call the field crate's
/// `register()` (e.g. `provekit_field_bn254::register()`) first.
pub(crate) fn provider() -> &'static dyn FieldHashProvider {
    *FIELD_HASH_PROVIDER.get().expect(
        "field hash provider not registered; call the field crate's register() at startup (e.g. \
         provekit_field_bn254::register())",
    )
}
