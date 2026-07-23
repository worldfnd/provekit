// The on-disk file-format glue lives behind the `io` module, which is not
// compiled for wasm (no filesystem). wasm serializes proofs via serde/postcard
// instead, so gate these impls out there.
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    binary_format,
    file::{Compression, FileFormat, MaybeHashAware},
};
#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{
        field::{Base, Ext, FieldHash, ProofField},
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
pub const MIN_WHIR_NUM_VARIABLES: usize = 13;

/// WHIR folding factors, shared by the witness and blinding commitments.
const WHIR_INITIAL_FOLDING_FACTOR: usize = 3;
const WHIR_FOLDING_FACTOR: usize = 3;

/// Domain floor for the ext blinding commitment: smallest WHIR domain valid for
/// the folding factors (not the witness floor — `g` is only `4 * m_0` coeffs).
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

/// WHIR proving/verifying parameters for one R1CS instance, generic over the
/// proof field `P`.
///
/// # Zero-knowledge
///
/// The ZK posture is fixed, not configurable:
/// - Sumcheck ZK is always on: the Spartan sumcheck rounds are masked by a
///   blinding polynomial `g`, committed separately in `whir_blinding`.
/// - Witness ZK is off: the witness is committed non-hiding in `whir_witness`,
///   whose WHIR openings leak witness values. It will be enabled by zkWHIR 3.0.
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
    /// Base-field witness commitment. Non-hiding — WHIR openings leak witness
    /// values, so this provides sumcheck ZK only, not witness ZK.
    /// TODO: make the witness commitment hiding for full witness ZK.
    pub whir_witness:      GenericWhirConfig<P::Embedding>,
    /// Separate ext-field commitment to the Spartan blinding polynomial `g`;
    /// masking the ext-valued sumcheck rounds needs ext randomness, so `g`
    /// cannot ride on the base witness commitment.
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
    /// Build a scheme for a concrete R1CS instance, recording its hash so the
    /// transcript can later be bound to this instance (in
    /// [`Self::create_domain_separator`]).
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
        let mut scheme = Self::new_from_dimensions(
            r1cs.num_witnesses(),
            r1cs.num_constraints(),
            r1cs.a().iter().count(),
            w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            hash_config,
        );
        scheme.r1cs_hash = r1cs.hash();
        scheme
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

    /// Shared WHIR parameters for the witness and blinding commitments: 128-bit
    /// security under the Johnson bound, rate 2, folding factor 3, pow_bits 10
    /// (≈118-bit algebraic hardness plus light per-round PoW).
    fn whir_protocol_params(hash_id: EngineId) -> ProtocolParameters {
        ProtocolParameters {
            decoding_regime: whir::protocols::params::DecodingRegime::Johnson,
            security_level: 128,
            pow_bits: 10,
            initial_folding_factor: WHIR_INITIAL_FOLDING_FACTOR,
            folding_factor: WHIR_FOLDING_FACTOR,
            starting_log_inv_rate: 2,
            batch_size: 1,
            hash_id,
        }
    }

    /// Build the non-ZK witness WHIR config: commits in `P`'s base field, opens
    /// at extension-field points.
    pub fn new_witness_config_for_size(
        num_variables: usize,
        hash_id: EngineId,
    ) -> GenericWhirConfig<P::Embedding> {
        let nv = num_variables.max(MIN_WHIR_NUM_VARIABLES);
        GenericWhirConfig::<P::Embedding>::new(1 << nv, &Self::whir_protocol_params(hash_id))
    }

    /// Build the WHIR config for the blinding polynomial `g`: its `4 * m_0`
    /// cubic coefficients committed in the ext field via `Identity`.
    pub fn new_blinding_config_for_size(
        m_0: usize,
        hash_id: EngineId,
    ) -> GenericWhirConfig<Identity<Ext<P>>> {
        let nv_blind = next_power_of_two(4 * m_0).max(MIN_BLINDING_NUM_VARIABLES);
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

/// Formats whose magic `.np` must never alias.
#[cfg(not(target_arch = "wasm32"))]
const NON_NP_FORMATS: [[u8; 8]; 3] = [
    binary_format::PROVER_FORMAT,
    binary_format::VERIFIER_FORMAT,
    binary_format::NOIR_PROOF_SCHEME_FORMAT,
];

#[cfg(not(target_arch = "wasm32"))]
const fn formats_eq(a: [u8; 8], b: [u8; 8]) -> bool {
    let mut i = 0;
    while i < 8 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Derive the `.np` format magic from [`ProofField::FIELD_ID`] by offsetting
/// the final magic byte: bn254 (id 0) keeps the historical magic, other fields
/// a distinct one.
///
/// The offset is a bijection on `u8`, so distinct ids always yield distinct
/// magics — at the cost of reserving all 256 values of the final byte.
#[cfg(not(target_arch = "wasm32"))]
const fn np_format(field_id: u8) -> [u8; 8] {
    let mut f = binary_format::NOIR_PROOF_FORMAT;
    f[7] = f[7].wrapping_add(field_id);

    let mut i = 0;
    while i < NON_NP_FORMATS.len() {
        assert!(
            !formats_eq(f, NON_NP_FORMATS[i]),
            "FIELD_ID makes the `.np` magic collide with another ProveKit file format"
        );
        i += 1;
    }
    f
}

#[cfg(not(target_arch = "wasm32"))]
impl<P: ProofField> FileFormat for ProvekitProof<P> {
    const FORMAT: [u8; 8] = np_format(<P as ProofField>::FIELD_ID);
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        super::{binary_format, np_format, NON_NP_FORMATS},
        std::collections::HashSet,
    };

    #[test]
    fn np_format_preserves_bn254() {
        assert_eq!(np_format(0), binary_format::NOIR_PROOF_FORMAT);
    }

    #[test]
    fn np_format_is_collision_free_over_every_field_id() {
        let magics: HashSet<[u8; 8]> = (0..=u8::MAX).map(np_format).collect();
        assert_eq!(magics.len(), 256, "FIELD_ID -> magic must be injective");
        for other in NON_NP_FORMATS {
            assert!(
                !magics.contains(&other),
                "`.np` magic space collides with {:?}",
                std::str::from_utf8(&other)
            );
        }
    }
}
