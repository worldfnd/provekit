#[cfg(all(feature = "bn254", not(target_arch = "wasm32")))]
use mavros_artifacts::R1CS as MavrosR1CS;
#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{
        utils::{next_power_of_two, serde_hex},
        FieldElement, HashConfig, R1CS,
    },
    anyhow::{ensure, Result},
    serde::{Deserialize, Serialize},
    whir::{
        algebra::embedding::Identity,
        engines::EngineId,
        parameters::ProtocolParameters,
        protocols::{whir::Config as GenericWhirConfig, whir_zk::Config as GenericWhirZkConfig},
        transcript,
    },
};

pub type WhirConfig = GenericWhirConfig<Identity<FieldElement>>;
pub type WhirZkConfig = GenericWhirZkConfig<FieldElement>;

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
pub struct WhirR1CSScheme {
    pub m:                 usize,
    pub w1_size:           usize,
    pub m_0:               usize,
    pub a_num_terms:       usize,
    pub num_challenges:    usize,
    pub challenge_offsets: Vec<usize>,
    pub has_public_inputs: bool,
    pub whir_witness:      WhirZkConfig,
    pub r1cs_hash:         R1csHash,
    /// Hash configuration for Merkle commitments, Fiat-Shamir sponge, and
    /// public-input instance binding. Source of truth; the WHIR engine ID
    /// stored inside `whir_witness` is derived from this at construction.
    pub hash_config:       HashConfig,
}

impl WhirR1CSScheme {
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

const MIN_WHIR_NUM_VARIABLES: usize = 13;
const MIN_SUMCHECK_NUM_VARIABLES: usize = 1;

/// Constructors for [`WhirR1CSScheme`], sizing the WHIR configuration from an
/// R1CS instance (or raw dimensions) and stamping the instance-binding
/// `r1cs_hash`.
pub trait WhirR1CSSchemeBuilder: Sized {
    /// Build a scheme for `r1cs`, stamping `r1cs_hash = r1cs.hash()`.
    ///
    /// Errors if `num_challenges != challenge_offsets.len()` or if `w1_size`
    /// exceeds the R1CS witness count.
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self>;

    /// Build a scheme from a Mavros R1CS, leaving `r1cs_hash` unset.
    ///
    /// Errors on the same dimension inconsistencies as
    /// [`Self::new_from_dimensions`].
    #[cfg(all(feature = "bn254", not(target_arch = "wasm32")))]
    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self>;

    /// Build a scheme from raw dimensions, leaving `r1cs_hash` unset.
    ///
    /// Errors if `num_challenges != challenge_offsets.len()` or if `w1_size`
    /// exceeds `num_witnesses`.
    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self>;

    /// Build the WHIR ZK configuration for `num_variables` (clamped to the
    /// protocol minimum) and `num_polynomials`.
    fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> WhirZkConfig;
}

impl WhirR1CSSchemeBuilder for WhirR1CSScheme {
    fn new_for_r1cs(
        r1cs: &R1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self> {
        ensure!(
            num_challenges == challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
        let total_witnesses = r1cs.num_witnesses();
        ensure!(
            w1_size <= total_witnesses,
            "w1_size ({w1_size}) exceeds total witnesses ({total_witnesses})"
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

        Ok(Self {
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
        })
    }

    fn new_whir_zk_config_for_size(
        num_variables: usize,
        num_polynomials: usize,
        hash_id: EngineId,
    ) -> WhirZkConfig {
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
        WhirZkConfig::new(1 << nv, &whir_params, num_polynomials)
    }

    #[cfg(all(feature = "bn254", not(target_arch = "wasm32")))]
    fn new_from_mavros_r1cs(
        r1cs: &MavrosR1CS,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self> {
        let num_witnesses = r1cs.witness_layout.size();
        let num_constraints = r1cs.constraints.len();
        let a_num_entries: usize = r1cs.constraints.iter().map(|c| c.a.len()).sum();

        Self::new_from_dimensions(
            num_witnesses,
            num_constraints,
            a_num_entries,
            w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            hash_config,
        )
    }

    fn new_from_dimensions(
        num_witnesses: usize,
        num_constraints: usize,
        a_num_entries: usize,
        w1_size: usize,
        num_challenges: usize,
        challenge_offsets: Vec<usize>,
        has_public_inputs: bool,
        hash_config: HashConfig,
    ) -> Result<Self> {
        ensure!(
            num_challenges == challenge_offsets.len(),
            "num_challenges ({num_challenges}) != challenge_offsets.len() ({})",
            challenge_offsets.len()
        );
        ensure!(
            w1_size <= num_witnesses,
            "w1_size ({w1_size}) exceeds total witnesses ({num_witnesses})"
        );
        let m_raw = next_power_of_two(num_witnesses);
        let m0_raw = next_power_of_two(num_constraints);

        let mut m = m_raw.max(MIN_WHIR_NUM_VARIABLES);
        let m_0 = m0_raw.max(MIN_SUMCHECK_NUM_VARIABLES);

        // Ensure w1's zero-padding has room for the blinding polynomial coefficients.
        if (1usize << m) - w1_size < 4 * m_0 {
            m += 1;
        }

        Ok(Self {
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
        })
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
    fn verify_security_level() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(20, 1, whir::hash::SHA2);
        let sec_blinded = config
            .blinded_commitment
            .security_level(config.blinded_commitment.initial_committer.num_vectors, 1);
        let sec_blinding = config
            .blinding_commitment
            .security_level(config.blinding_commitment.initial_committer.num_vectors, 1);
        assert!(
            sec_blinded >= 128.0,
            "Blinded commitment security {sec_blinded:.2} < 128 bits"
        );
        assert!(
            sec_blinding >= 128.0,
            "Blinding commitment security {sec_blinding:.2} < 128 bits"
        );
    }

    #[test]
    fn verify_security_level_min_variables() {
        let config = WhirR1CSScheme::new_whir_zk_config_for_size(
            MIN_WHIR_NUM_VARIABLES,
            1,
            whir::hash::SHA2,
        );
        let sec_blinded = config
            .blinded_commitment
            .security_level(config.blinded_commitment.initial_committer.num_vectors, 1);
        let sec_blinding = config
            .blinding_commitment
            .security_level(config.blinding_commitment.initial_committer.num_vectors, 1);
        assert!(
            sec_blinded >= 128.0,
            "Blinded commitment security {sec_blinded:.2} < 128 bits at nv={}",
            MIN_WHIR_NUM_VARIABLES
        );
        assert!(
            sec_blinding >= 128.0,
            "Blinding commitment security {sec_blinding:.2} < 128 bits at nv={}",
            MIN_WHIR_NUM_VARIABLES
        );
    }
}
