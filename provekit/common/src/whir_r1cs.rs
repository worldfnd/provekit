#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{
        field::{Base, Ext, ProofField},
        utils::serde_hex,
        HashConfig, PublicInputs,
    },
    serde::{Deserialize, Serialize},
    whir::{protocols::whir_zk::Config as GenericWhirZkConfig, transcript},
};

// The on-disk file-format glue lives behind the `io` module, which is not
// compiled for wasm (no filesystem). wasm serializes proofs via serde/postcard
// instead, so gate these impls out there.
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    binary_format,
    file::{Compression, FileFormat, MaybeHashAware},
};

/// Type alias for the whir domain separator used in provekit's outer protocol.
type WhirDomainSeparator = transcript::DomainSeparator<'static, ()>;

/// SHA3-256 hash of a serialized R1CS instance, used to bind the Fiat-Shamir
/// transcript to a concrete circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csHash([u8; 32]);

impl R1csHash {
    /// Sentinel value for paths that don't have an R1CS at construction time
    /// (e.g. `new_from_dimensions`). Will trigger a debug assertion if used
    /// in `create_domain_separator`.
    pub const UNSET: Self = Self([0u8; 32]);

    /// Wrap a raw 32-byte digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WhirR1CSScheme<P: ProofField> {
    pub m:                 usize,
    pub w1_size:           usize,
    pub m_0:               usize,
    pub a_num_terms:       usize,
    pub num_challenges:    usize,
    pub challenge_offsets: Vec<usize>,
    pub has_public_inputs: bool,
    pub whir_witness:      GenericWhirZkConfig<Ext<P>>,
    pub r1cs_hash:         R1csHash,
    /// Hash configuration for Merkle commitments, Fiat-Shamir sponge, and
    /// public-input instance binding. Source of truth; the WHIR engine ID
    /// stored inside `whir_witness` is derived from this at construction.
    pub hash_config:       HashConfig,
}

impl<P: ProofField> WhirR1CSScheme<P> {
    /// Return the witness commitment domain size.
    pub const fn domain_size(&self) -> usize {
        1usize << self.m
    }

    /// Create a domain separator for the provekit outer protocol.
    ///
    /// The domain separator serializes the entire scheme (including
    /// `r1cs_hash`) into the protocol ID, binding the Fiat-Shamir
    /// transcript to the concrete R1CS instance.
    pub fn create_domain_separator(&self) -> WhirDomainSeparator {
        debug_assert_ne!(
            self.r1cs_hash,
            R1csHash::UNSET,
            "R1CS hash is uninitialized — transcript will not be bound to a concrete circuit"
        );
        transcript::DomainSeparator::protocol(self)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub narg_string: Vec<u8>,
    #[serde(with = "serde_hex")]
    pub hints:       Vec<u8>,

    /// Transcript interaction pattern for debug-mode validation.
    /// Populated by the prover; absent from serialized proofs on disk.
    #[cfg(debug_assertions)]
    #[serde(skip)]
    pub pattern: Vec<Interaction>,
}

/// A ProveKit proof: the public inputs bound to the instance plus the WHIR
/// proof payload. Produced by any frontend (Noir, Mavros), generic over the
/// proof field — the payload is field-agnostic bytes and the public inputs
/// live in the base field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProvekitProof<P: ProofField> {
    pub public_inputs:   PublicInputs<Base<P>>,
    pub whir_r1cs_proof: WhirR1CSProof,
}

#[cfg(not(target_arch = "wasm32"))]
impl<P: ProofField> FileFormat for ProvekitProof<P> {
    const FORMAT: [u8; 8] = binary_format::NOIR_PROOF_FORMAT;
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = binary_format::NOIR_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

#[cfg(not(target_arch = "wasm32"))]
impl<P: ProofField> MaybeHashAware for ProvekitProof<P> {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}
