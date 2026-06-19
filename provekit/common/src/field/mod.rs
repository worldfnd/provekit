//! Field-specific proof operations behind a registered provider.
//!
//! `common` names no concrete field. A field crate (e.g.
//! `provekit-field-bn254`) registers a [`FieldHashProvider`] via
//! [`register_field_hash_provider`], and the spine looks it up at runtime, like
//! whir's `ENGINES`/`NTT` registries.

use {
    crate::{hash_config::FieldNativeHashConfig, FieldElement},
    anyhow::{Context, Result},
    spongefish::DuplexSpongeInterface,
    std::sync::OnceLock,
    whir::engines::EngineId,
};

/// Object-safe Fiat-Shamir sponge for the field-native hash configs.
///
/// Lets `TranscriptSponge` box a field-native sponge: `spongefish`'s
/// `DuplexSpongeInterface` returns `&mut Self`, so it is not object-safe.
///
/// The methods are prefixed `fs_` so they do not shadow
/// `DuplexSpongeInterface`'s `absorb`/`squeeze`/`ratchet`. The blanket impl
/// below makes every byte sponge also a `DynFieldSponge`, so identical names
/// would make a bare `s.absorb(..)` ambiguous at any call site where both
/// traits are in scope.
pub trait DynFieldSponge: Send {
    /// Absorb bytes into the sponge.
    fn fs_absorb(&mut self, input: &[u8]);
    /// Squeeze bytes out of the sponge.
    fn fs_squeeze(&mut self, output: &mut [u8]);
    /// Ratchet the sponge state.
    fn fs_ratchet(&mut self);
    /// Clone into a fresh box (enables `#[derive(Clone)]` on the holder).
    fn clone_box(&self) -> Box<dyn DynFieldSponge>;
}

/// Any `Clone` byte-sponge from `spongefish` is automatically a
/// `DynFieldSponge`.
///
/// This blanket impl (rather than explicit impls in the field crate) is forced
/// by coherence: the concrete sponges are `spongefish::DuplexSponge<..>`
/// aliases — a foreign type — and `DynFieldSponge` is foreign to the field
/// crate too, so the field crate cannot implement it for them (orphan rule).
impl<S> DynFieldSponge for S
where
    S: DuplexSpongeInterface<U = u8> + Clone + Send + 'static,
{
    fn fs_absorb(&mut self, input: &[u8]) {
        DuplexSpongeInterface::absorb(self, input);
    }

    fn fs_squeeze(&mut self, output: &mut [u8]) {
        DuplexSpongeInterface::squeeze(self, output);
    }

    fn fs_ratchet(&mut self) {
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

    /// Construct the field-native Fiat-Shamir sponge for `config`.
    fn field_sponge(&self, config: FieldNativeHashConfig) -> Box<dyn DynFieldSponge>;
}

static FIELD_HASH_PROVIDER: OnceLock<&'static dyn FieldHashProvider> = OnceLock::new();

/// Register the field-native hash provider, called once at startup by the field
/// crate's `register()`. The first registrant wins; a later call (even with a
/// different provider) is ignored, so a binary must register exactly one field
/// crate.
pub fn register_field_hash_provider(provider: &'static dyn FieldHashProvider) {
    // Each field crate's `register()` is `Once`-guarded, so a failed `set` here
    // means a *different* field crate already registered — a wrong-field bug once
    // more than one field backend exists. Catch it in debug builds. (The `set`
    // runs unconditionally; only the check is debug-gated.)
    let first = FIELD_HASH_PROVIDER.set(provider).is_ok();
    debug_assert!(
        first,
        "a field hash provider is already registered; a binary must register exactly one field \
         crate",
    );
}

/// Access the registered field-native hash provider, or an error if no field
/// crate has registered one.
pub(crate) fn try_provider() -> Result<&'static dyn FieldHashProvider> {
    FIELD_HASH_PROVIDER.get().copied().context(
        "field hash provider not registered; call the field crate's register() at startup (e.g. \
         provekit_field_bn254::register())",
    )
}

/// Confirm a field backend has been registered, returning an error otherwise.
///
/// Call this at the top of an entry point that does not itself register a
/// backend (e.g. verification) so a forgotten `register()` surfaces as a clean
/// error instead of a panic deep in a field-native hash path.
pub fn ensure_field_backend_registered() -> Result<()> {
    try_provider().map(|_| ())
}
