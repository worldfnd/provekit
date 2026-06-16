//! Field-specific proof operations behind a registered provider.
//!
//! The spine is field-agnostic: it never names `skyscraper`, `poseidon2`, or
//! `ntt`. Instead a field crate (e.g. `provekit-field-bn254`) registers a
//! [`FieldHashProvider`] at startup via [`register_field_hash_provider`], and
//! the spine looks it up at runtime — the same pattern whir uses for its
//! `ENGINES` / `NTT` registries.
//!
//! This keeps `common` free of any concrete-field dependency: a binary links
//! exactly the one field crate it registers, and adding a field is a new crate
//! plus a `register()` call, with no change here.

use {
    crate::{FieldElement, HashConfig},
    spongefish::DuplexSpongeInterface,
    std::sync::OnceLock,
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
/// [`FieldHashProvider::field_sponge`]) is field-specific.
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

/// The per-field glue the spine needs but whir's `Embedding` trait does not
/// provide: the field-native Merkle-hash engine ids, the public-input binding
/// hashes, and the field-native Fiat-Shamir sponge constructor.
///
/// Implemented and registered by a field crate (e.g. `provekit-field-bn254`).
/// Object-safe so the spine can hold it as `&'static dyn FieldHashProvider`.
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

/// Register the field-native hash provider. Called once at startup by the
/// active field crate's `register()`. Idempotent: later calls are ignored.
pub fn register_field_hash_provider(provider: &'static dyn FieldHashProvider) {
    let _ = FIELD_HASH_PROVIDER.set(provider);
}

/// Access the registered field-native hash provider.
///
/// # Panics
/// Panics if no provider has been registered — call the active field crate's
/// `register()` (e.g. `provekit_field_bn254::register()`) before any
/// proving/verifying or public-input hashing under the Skyscraper/Poseidon2
/// configurations.
pub(crate) fn provider() -> &'static dyn FieldHashProvider {
    *FIELD_HASH_PROVIDER.get().expect(
        "field hash provider not registered; call the field crate's register() at startup (e.g. \
         provekit_field_bn254::register())",
    )
}
