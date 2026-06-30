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
        algebra::embedding::Identity, engines::EngineId, parameters::ProtocolParameters,
        protocols::whir::Config as GenericWhirConfig, transcript,
    },
};

/// WHIR witness-domain floor: prover work is flat at or below `2^13` variables,
/// so smaller commitments are padded up to this many variables.
const MIN_WHIR_NUM_VARIABLES: usize = 13;

/// WHIR folding factors, shared by the witness and blinding commitments via
/// `whir_protocol_params`. The blinding domain floor is derived from these so
/// the two cannot silently desync.
const WHIR_INITIAL_FOLDING_FACTOR: usize = 3;
const WHIR_FOLDING_FACTOR: usize = 3;

/// Domain floor for the ext blinding commitment. The blinding vector holds only
/// `4 * m_0` coefficients, so it does NOT use the witness floor
/// ([`MIN_WHIR_NUM_VARIABLES`], a witness-specific performance plateau) — that
/// would inflate the proof for no soundness benefit. This is the smallest WHIR
/// domain that remains valid for the configured folding factors.
const MIN_BLINDING_NUM_VARIABLES: usize = WHIR_INITIAL_FOLDING_FACTOR + WHIR_FOLDING_FACTOR;

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
    /// Witness commitment, over the base field (`P::Embedding` has base
    /// leaves).
    ///
    /// This path provides **sumcheck** zero-knowledge only. The base witness
    /// commitment is NOT hiding — its WHIR/FRI query openings still leak
    /// witness values; the Spartan sumcheck round polynomials are hidden by
    /// the separate ext blinding commitment below.
    /// TODO: make the witness commitment itself hiding for full witness
    /// zero-knowledge.
    pub whir_witness:      GenericWhirConfig<P::Embedding>,
    /// Separate extension-field commitment to the Spartan sumcheck blinding
    /// polynomial `g`. Kept distinct from the base witness commitment so the
    /// mask lives natively in the challenge (extension) field — masking the
    /// ext-valued sumcheck round polynomials requires ext randomness.
    pub whir_blinding:     GenericWhirConfig<Identity<Ext<P>>>,
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

    /// Return the Spartan-blinding commitment domain size.
    pub fn blinding_domain_size(&self) -> usize {
        1usize << self.whir_blinding.initial_num_variables()
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
    /// The witness commitment domain size, sumcheck rounds, and blinding
    /// commitment size are derived purely from R1CS dimensions.
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

        let m_raw = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        Self {
            m: m_raw,
            w1_size,
            m_0,
            a_num_terms: next_power_of_two(r1cs.a().iter().count()),
            num_challenges,
            challenge_offsets,
            whir_witness: Self::new_witness_config_for_size(m_raw, hash_config.engine_id()),
            whir_blinding: Self::new_blinding_config_for_size(m_0, hash_config.engine_id()),
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

        let m = m1_raw.max(m2_raw).max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        Self {
            m,
            m_0,
            a_num_terms: next_power_of_two(a_num_entries),
            whir_witness: Self::new_witness_config_for_size(m, hash_config.engine_id()),
            whir_blinding: Self::new_blinding_config_for_size(m_0, hash_config.engine_id()),
            w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            r1cs_hash: R1csHash::UNSET,
            hash_config,
        }
    }

    /// Shared WHIR protocol parameters for both the witness and blinding
    /// commitments.
    ///
    /// Tuned for 128-bit security under the Johnson bound (the old
    /// ConjectureList soundness was disproven). Rate=2 balances query count vs
    /// codeword size; ff=3 keeps folding cheap; pow_bits=10 shifts security
    /// budget toward algebraic hardness (118 bits) with light PoW per round,
    /// which is faster than the default ~18-bit grinding.
    fn whir_protocol_params(hash_id: EngineId) -> ProtocolParameters {
        ProtocolParameters {
            unique_decoding: false,
            security_level: 128,
            pow_bits: 10,
            initial_folding_factor: WHIR_INITIAL_FOLDING_FACTOR,
            folding_factor: WHIR_FOLDING_FACTOR,
            starting_log_inv_rate: 2,
            batch_size: 1,
            hash_id,
        }
    }

    /// Build the (non-ZK) WHIR configuration for the witness of
    /// `num_variables`, committing in the base field of `P` and opening at
    /// points in the extension field.
    pub fn new_witness_config_for_size(
        num_variables: usize,
        hash_id: EngineId,
    ) -> GenericWhirConfig<P::Embedding> {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);
        GenericWhirConfig::<P::Embedding>::new(1 << nv, &Self::whir_protocol_params(hash_id))
    }

    /// Build the WHIR configuration for the Spartan blinding polynomial `g`,
    /// committing the `4 * m_0` cubic coefficients natively in the extension
    /// (challenge) field via the `Identity` embedding.
    pub fn new_blinding_config_for_size(
        m_0: usize,
        hash_id: EngineId,
    ) -> GenericWhirConfig<Identity<Ext<P>>> {
        let nv_blind = ((4 * m_0).next_power_of_two().trailing_zeros() as usize)
            .max(MIN_BLINDING_NUM_VARIABLES);
        GenericWhirConfig::<Identity<Ext<P>>>::new(
            1 << nv_blind,
            &Self::whir_protocol_params(hash_id),
        )
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

/// Derive the `.np` format magic for a given [`ProofField::FIELD_ID`].
///
/// The base magic [`binary_format::NOIR_PROOF_FORMAT`] is used verbatim for
/// bn254 (`field_id == 0`); other fields offset the final byte so a proof from
/// one field fails the format check when read by a verifier of another. The
/// header layout is unchanged — only this 8-byte magic varies by field.
const fn np_format(field_id: u8) -> [u8; 8] {
    let mut f = binary_format::NOIR_PROOF_FORMAT;
    f[7] = f[7].wrapping_add(field_id);
    f
}

impl<P: ProofField> FileFormat for ProvekitProof<P> {
    const FORMAT: [u8; 8] = np_format(<P as ProofField>::FIELD_ID);
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = binary_format::NOIR_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl<P: ProofField> MaybeHashAware for ProvekitProof<P> {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{binary_format, np_format};

    #[test]
    fn np_format_preserves_bn254_and_distinguishes_fields() {
        // bn254 (id 0) must stay byte-identical to the historical magic.
        assert_eq!(np_format(0), binary_format::NOIR_PROOF_FORMAT);
        // Other fields produce distinct magics from bn254 and each other.
        assert_ne!(np_format(1), np_format(0));
        assert_ne!(np_format(2), np_format(0));
        assert_ne!(np_format(2), np_format(1));
    }
}
