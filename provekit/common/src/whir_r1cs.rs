#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{
        field::{Base, Ext, FieldHash, ProofField},
        utils::{bytes_to_field, field_to_bytes_le, serde_hex},
        FieldElement, HashConfig,
    },
    serde::{Deserialize, Serialize},
    whir::{
        algebra::embedding::Identity,
        protocols::{whir::Config as GenericWhirConfig, whir_zk::Config as GenericWhirZkConfig},
        transcript,
    },
};

// TODO(P0.4): bn254-concrete aliases — relocate to provekit-backend-bn254.
pub type WhirConfig = GenericWhirConfig<Identity<FieldElement>>;
pub type WhirZkConfig = GenericWhirZkConfig<FieldElement>;

/// bn254 proof field: the `Identity<Fr>` embedding (base == ext).
// TODO(P0.4): relocate Bn254Field + its ProofField/FieldHash impls to
// provekit-backend-bn254 (the hash bodies move with it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254Field;

impl ProofField for Bn254Field {
    type Embedding = Identity<FieldElement>;
}

impl FieldHash for Bn254Field {
    fn default_hash() -> HashConfig {
        HashConfig::Skyscraper
    }

    fn hash_public_inputs(config: HashConfig, inputs: &[Base<Self>]) -> Ext<Self> {
        config.hash_field_elements(inputs)
    }

    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8> {
        field_to_bytes_le(*x).to_vec()
    }

    fn ext_from_bytes(bytes: &[u8]) -> Ext<Self> {
        bytes_to_field(bytes)
    }

    fn from_digest(digest: &[u8]) -> Ext<Self> {
        bytes_to_field(digest)
    }
}

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
pub struct WhirR1CSScheme<P: ProofField = Bn254Field> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bn254_field_hash_roundtrip() {
        let x: Ext<Bn254Field> = FieldElement::from(123_456_789u64);
        let bytes = Bn254Field::ext_to_bytes_le(&x);
        assert_eq!(bytes.len(), 32);
        assert_eq!(Bn254Field::ext_from_bytes(&bytes), x);
        assert_eq!(Bn254Field::from_digest(&bytes), x);
        assert_eq!(Bn254Field::default_hash(), HashConfig::Skyscraper);
    }

    // TODO(P0.4): once the spine routes public-input hashing through
    // `FieldHash::hash_public_inputs` and `PublicInputs::hash` is removed,
    // convert this differential test to a hardcoded byte fixture (the P0.7
    // bn254 bit-identical gate).
    #[test]
    fn bn254_hash_public_inputs_matches_public_inputs_hash() {
        let inputs = [FieldElement::from(7u64), FieldElement::from(42u64)];
        let pi = crate::PublicInputs::from_vec(inputs.to_vec());
        for config in [
            HashConfig::Skyscraper,
            HashConfig::Sha256,
            HashConfig::Keccak,
            HashConfig::Blake3,
            HashConfig::Poseidon2,
        ] {
            assert_eq!(
                Bn254Field::hash_public_inputs(config, &inputs),
                pi.hash(config),
                "mismatch for {config:?}"
            );
        }
    }
}
