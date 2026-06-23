#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{
        binary_format,
        field::{Base, Ext, FieldHash, ProofField},
        file::{Compression, FileFormat, MaybeHashAware},
        utils::{next_power_of_two, serde_hex},
        HashConfig, PublicInputs, R1CS,
    },
    serde::{Deserialize, Serialize},
    whir::{
        engines::EngineId, parameters::ProtocolParameters,
        protocols::whir_zk::Config as GenericWhirZkConfig, transcript,
    },
};

/// WHIR witness-domain floor: prover work is flat at or below `2^13` variables,
/// so smaller commitments are padded up to this many variables.
const MIN_WHIR_NUM_VARIABLES: usize = 13;

/// Minimum sumcheck rounds, keeping the constraint-domain polynomial
/// non-trivial.
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

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

impl<P: FieldHash> WhirR1CSScheme<P> {
    /// Build a scheme for a concrete R1CS instance, binding the transcript to
    /// the R1CS hash.
    ///
    /// Witness commitment domain size, sumcheck rounds, blinding room, and the
    /// zkWHIR configuration are derived purely from R1CS dimensions.
    pub fn new_for_r1cs(
        r1cs: &R1CS<Base<P>>,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self {
        assert_eq!(
            num_challenges,
            challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
        let total_witnesses = r1cs.num_witnesses();
        assert!(
            w1_size <= total_witnesses,
            "w1_size exceeds total witnesses"
        );
        let w2_size = total_witnesses - w1_size;

        let m1_raw = next_power_of_two(w1_size);
        let m2_raw = next_power_of_two(w2_size);
        let m0_raw = next_power_of_two(r1cs.num_constraints());

        let mut m_raw = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Ensure w1's zero-padding has room for the blinding polynomial coefficients.
        if (1usize << m_raw) - w1_size < 4 * m_0 {
            m_raw += 1;
        }

        Self {
            m: m_raw,
            w1_size,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            num_challenges,
            challenge_offsets,
            whir_witness: Self::new_whir_zk_config_for_size(m_raw, 1, hash_config.engine_id()),
            has_public_inputs,
            r1cs_hash: r1cs.hash(),
            hash_config,
        }
    }

    /// Build a scheme from raw dimensions, leaving `r1cs_hash` unset (the
    /// caller must populate it before creating a domain separator).
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Self {
        assert_eq!(
            num_challenges,
            challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
        assert!(w1_size <= num_witnesses, "w1_size exceeds total witnesses");
        let w2_size = num_witnesses - w1_size;

        let m1_raw = next_power_of_two(w1_size);
        let m2_raw = next_power_of_two(w2_size);
        let m0_raw = next_power_of_two(num_constraints);

        let mut m = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Ensure w1's zero-padding has room for the blinding polynomial coefficients.
        if (1usize << m) - w1_size < 4 * m_0 {
            m += 1;
        }

        Self {
            m,
            m_0,
            a_num_terms: next_power_of_two(a_num_entries),
            whir_witness: Self::new_whir_zk_config_for_size(m, 1, hash_config.engine_id()),
            w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            r1cs_hash: R1csHash::UNSET,
            hash_config,
        }
    }

    /// Build the zkWHIR configuration for a polynomial of `num_variables` over
    /// the extension (challenge) field of `P`.
    pub fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> GenericWhirZkConfig<Ext<P>> {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);

        // Parameters tuned for 128-bit security under the Johnson bound (the old
        // ConjectureList soundness was disproven). Rate=2 balances query count vs
        // codeword size; ff=3 keeps blinding polynomials small; pow_bits=10 shifts
        // security budget toward algebraic hardness (118 bits) with light PoW per
        // round, which is faster than the default ~18-bit grinding.
        let whir_params = ProtocolParameters {
            unique_decoding: false,
            security_level: 128,
            pow_bits: 10,
            initial_folding_factor: 3,
            folding_factor: 3,
            starting_log_inv_rate: 2,
            batch_size: 1,
            hash_id,
        };
        GenericWhirZkConfig::<Ext<P>>::new(1 << nv, &whir_params, num_polynomials)
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

impl<P: ProofField> FileFormat for ProvekitProof<P> {
    const FORMAT: [u8; 8] = binary_format::NOIR_PROOF_FORMAT;
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = binary_format::NOIR_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl<P: ProofField> MaybeHashAware for ProvekitProof<P> {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}
