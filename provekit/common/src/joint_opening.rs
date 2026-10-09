//! Interface for one opening of two ordered witness commitments.
//!
//! ProveKit supplies the two source commitments and forms over their combined
//! domain. WHIR supplies the joint protocol through [`JointOpeningBackend`].

use {
    crate::{Ext, FieldHash},
    anyhow::{ensure, Result},
    ark_ff::Field,
    serde::{Deserialize, Serialize},
    whir::{
        algebra::{embedding::Embedding, linear_form::LinearForm},
        protocols::zook::{
            Commitment, CommittedWitness, FinalClaim, ProtocolConfig as ZookConfig, ProverClaim,
        },
        transcript::{ProverState, VerifierState},
    },
};

/// Select separate openings or one joint opening for a two-stage witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WitnessOpeningMode {
    /// Use the existing opening for each commitment.
    #[default]
    Separate,
    /// Use the joint opening backend for both commitments.
    Joint,
}

impl std::str::FromStr for WitnessOpeningMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "separate" => Ok(Self::Separate),
            "joint" => Ok(Self::Joint),
            _ => Err(format!(
                "Invalid witness opening mode: '{value}'. Valid options: separate, joint"
            )),
        }
    }
}

/// Dimensions of the virtual witness `[w1 | w2]`.
///
/// Each source commitment has `block_size` entries.
/// The first evaluation coordinate selects a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointOpeningLayout {
    block_size:    usize,
    size:          usize,
    num_variables: usize,
}

impl JointOpeningLayout {
    /// Check the block size and derive the joint dimensions.
    pub fn new(block_size: usize) -> Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "Joint opening block size must be a nonzero power of two"
        );
        let size = block_size
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("Joint opening domain size exceeds usize"))?;
        Ok(Self {
            block_size,
            size,
            num_variables: size.trailing_zeros() as usize,
        })
    }

    /// Return the size of each source commitment.
    pub const fn block_size(self) -> usize {
        self.block_size
    }

    /// Return the combined form size.
    pub const fn size(self) -> usize {
        self.size
    }

    /// Return the evaluation point length, including the selector.
    pub const fn num_variables(self) -> usize {
        self.num_variables
    }

    /// Check source dimensions and the existing source configuration
    /// invariants.
    ///
    /// This check does not establish security for the joint protocol.
    /// The backend must also validate its joint configuration.
    pub fn validate_source_config<M: Embedding>(self, source: &ZookConfig<M>) -> Result<()> {
        ensure!(
            source.tuning().vector_size == self.block_size,
            "Joint opening source size {} does not match block size {}",
            source.tuning().vector_size,
            self.block_size
        );
        source
            .validate()
            .map_err(|error| anyhow::anyhow!("Invalid joint opening source configuration: {error}"))
    }

    /// Check that every value has one form over the combined domain.
    pub fn validate_claims<F: Field>(
        self,
        forms: &[&dyn LinearForm<F>],
        values: &[F],
    ) -> Result<()> {
        ensure!(
            !forms.is_empty(),
            "Joint opening requires at least one claim"
        );
        ensure!(
            forms.len() == values.len(),
            "Joint opening form count {} does not match value count {}",
            forms.len(),
            values.len()
        );
        for (index, form) in forms.iter().enumerate() {
            ensure!(
                form.size() == self.size,
                "Joint opening form {index} has size {}, expected {}",
                form.size(),
                self.size
            );
        }
        Ok(())
    }

    /// Check the complete evaluation point before evaluating combined forms.
    pub fn validate_point<F>(self, point: &[F]) -> Result<()> {
        ensure!(
            point.len() == self.num_variables,
            "Joint opening point has {} coordinates, expected {}",
            point.len(),
            self.num_variables
        );
        Ok(())
    }

    /// Check the dimensions of the backend prover result.
    pub fn validate_prover_claim<F: Field>(
        self,
        claim: &ProverClaim<F>,
        num_claims: usize,
    ) -> Result<()> {
        self.validate_point(&claim.evaluation_point)?;
        self.validate_coefficients(claim.rlc_coefficients.len(), num_claims)
    }

    /// Check the backend verifier result before its final form check.
    pub fn validate_final_claim<F: Field>(
        self,
        claim: &FinalClaim<F>,
        num_claims: usize,
    ) -> Result<()> {
        self.validate_point(&claim.evaluation_point)?;
        self.validate_coefficients(claim.rlc_coefficients.len(), num_claims)
    }

    fn validate_coefficients(self, actual: usize, expected: usize) -> Result<()> {
        ensure!(
            actual == expected,
            "Joint opening coefficient count {actual} does not match claim count {expected}"
        );
        Ok(())
    }
}

/// Backend contract for one proof over two existing commitments.
///
/// Array order fixes the selector: index 0 selects `w1`, and index 1 selects
/// `w2`. The backend must bind both commitments and all supplied form values.
/// It must preserve each source commitment mask in zero-knowledge mode.
/// It must return the complete point, with the selector coordinate first.
/// It must bind any derived joint configuration into the transcript.
/// Source configuration security alone does not establish joint protocol
/// security. Callers must validate the result dimensions and finish the
/// verifier's final form check.
pub trait JointOpeningBackend<P: FieldHash> {
    /// Check availability, source invariants, and security of the derived joint
    /// configuration.
    ///
    /// Call this method before committing or changing the transcript.
    fn validate(&self, source: &ZookConfig<P::Embedding>, layout: JointOpeningLayout)
        -> Result<()>;

    /// Prove the supplied claims against the two ordered source witnesses.
    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        transcript: &mut ProverState<P::Sponge>,
        source: &ZookConfig<P::Embedding>,
        layout: JointOpeningLayout,
        witnesses: [CommittedWitness<P::Embedding>; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<ProverClaim<Ext<P>>>;

    /// Verify the supplied claims against the two ordered source commitments.
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        transcript: &mut VerifierState<'_, P::Sponge>,
        source: &ZookConfig<P::Embedding>,
        layout: JointOpeningLayout,
        commitments: [Commitment; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<FinalClaim<Ext<P>>>;
}

/// Explicit rejection until WHIR supplies a joint opening implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableJointOpening;

impl<P: FieldHash> JointOpeningBackend<P> for UnavailableJointOpening {
    fn validate(
        &self,
        source: &ZookConfig<P::Embedding>,
        layout: JointOpeningLayout,
    ) -> Result<()> {
        layout.validate_source_config(source)?;
        Err(joint_opening_unavailable())
    }

    fn prove(
        &self,
        _transcript: &mut ProverState<P::Sponge>,
        source: &ZookConfig<P::Embedding>,
        layout: JointOpeningLayout,
        _witnesses: [CommittedWitness<P::Embedding>; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<ProverClaim<Ext<P>>> {
        layout.validate_source_config(source)?;
        layout.validate_claims(forms, values)?;
        Err(joint_opening_unavailable())
    }

    fn verify(
        &self,
        _transcript: &mut VerifierState<'_, P::Sponge>,
        source: &ZookConfig<P::Embedding>,
        layout: JointOpeningLayout,
        _commitments: [Commitment; 2],
        forms: &[&dyn LinearForm<Ext<P>>],
        values: &[Ext<P>],
    ) -> Result<FinalClaim<Ext<P>>> {
        layout.validate_source_config(source)?;
        layout.validate_claims(forms, values)?;
        Err(joint_opening_unavailable())
    }
}

fn joint_opening_unavailable() -> anyhow::Error {
    anyhow::anyhow!(
        "Joint witness opening is unavailable: WHIR must supply the joint opening backend; use \
         separate witness openings"
    )
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::PrefixCovector,
        whir::{
            algebra::{embedding::Identity, fields::Field64},
            protocols::params::{
                DecodingRegime, FoldingFactor, Mode, PowBudget, RateSchedule, SecuritySpec,
                TuningSpec,
            },
        },
    };

    fn field(value: u64) -> Field64 {
        Field64::from(value)
    }

    #[test]
    fn two_blocks_of_four_need_eight_entries_and_three_coordinates() {
        let layout = JointOpeningLayout::new(4).unwrap();
        assert_eq!(layout.block_size(), 4);
        assert_eq!(layout.size(), 8);
        assert_eq!(layout.num_variables(), 3);
    }

    #[test]
    fn a_single_entry_block_still_needs_a_selector() {
        let layout = JointOpeningLayout::new(1).unwrap();
        assert_eq!(layout.size(), 2);
        assert_eq!(layout.num_variables(), 1);
    }

    #[test]
    fn zero_and_non_power_of_two_blocks_are_rejected() {
        for block_size in [0, 3, 6] {
            assert!(JointOpeningLayout::new(block_size).is_err());
        }
    }

    #[test]
    fn an_overflowing_joint_domain_is_rejected() {
        let largest_power_of_two = 1usize << (usize::BITS - 1);
        assert!(JointOpeningLayout::new(largest_power_of_two).is_err());
    }

    #[test]
    fn the_source_configuration_must_match_each_block() {
        let source = ZookConfig::<Identity<Field64>>::derive(
            SecuritySpec {
                mode:                 Mode::Standard,
                decoding_regime:      DecodingRegime::Johnson,
                target_security_bits: 40,
                pow_budget:           PowBudget::per_slot(10),
                hash_id:              whir::hash::BLAKE3,
            },
            TuningSpec {
                vector_size:           8,
                starting_log_inv_rate: 1,
                folding_factor:        FoldingFactor::Constant(2),
                rate_schedule:         RateSchedule::Stepping,
            },
        )
        .unwrap();

        assert!(JointOpeningLayout::new(8)
            .unwrap()
            .validate_source_config(&source)
            .is_ok());
        assert!(JointOpeningLayout::new(4)
            .unwrap()
            .validate_source_config(&source)
            .is_err());
    }

    #[test]
    fn each_claim_needs_a_value_and_an_eight_entry_form() {
        let layout = JointOpeningLayout::new(4).unwrap();
        let correct = PrefixCovector::new(vec![field(2), field(3)], 8);
        let source_only = PrefixCovector::new(vec![field(2), field(3)], 4);

        assert!(layout.validate_claims(&[&correct], &[field(11)]).is_ok());
        assert!(layout.validate_claims(&[&correct], &[]).is_err());
        assert!(layout
            .validate_claims(&[&source_only], &[field(11)])
            .is_err());
        assert!(layout.validate_claims::<Field64>(&[], &[]).is_err());
    }

    #[test]
    fn a_point_without_the_selector_is_rejected() {
        let layout = JointOpeningLayout::new(4).unwrap();
        assert!(layout.validate_point(&[field(2), field(3)]).is_err());
        assert!(layout
            .validate_point(&[field(2), field(3), field(5)])
            .is_ok());
        assert!(layout
            .validate_point(&[field(2), field(3), field(5), field(7)])
            .is_err());
    }

    #[test]
    fn backend_results_need_one_coefficient_for_each_claim() {
        let layout = JointOpeningLayout::new(4).unwrap();
        let prover = ProverClaim {
            evaluation_point: vec![field(2), field(3), field(5)],
            rlc_coefficients: vec![field(1), field(7)],
        };
        let verifier = FinalClaim {
            evaluation_point:          prover.evaluation_point.clone(),
            initial_claim_scale:       field(1),
            linear_forms_contribution: field(11),
            rlc_coefficients:          prover.rlc_coefficients.clone(),
        };
        assert!(layout.validate_prover_claim(&prover, 2).is_ok());
        assert!(layout.validate_final_claim(&verifier, 2).is_ok());
        assert!(layout.validate_prover_claim(&prover, 3).is_err());
        assert!(layout.validate_final_claim(&verifier, 3).is_err());
    }

    #[test]
    fn separate_is_the_default_and_joint_requires_an_explicit_choice() {
        assert_eq!(WitnessOpeningMode::default(), WitnessOpeningMode::Separate);
        assert_eq!("separate".parse(), Ok(WitnessOpeningMode::Separate));
        assert_eq!("joint".parse(), Ok(WitnessOpeningMode::Joint));
        assert_eq!("JOINT".parse(), Ok(WitnessOpeningMode::Joint));
        assert!("jointly".parse::<WitnessOpeningMode>().is_err());
    }

    #[test]
    fn both_opening_modes_round_trip_through_json_and_postcard() {
        for mode in [WitnessOpeningMode::Separate, WitnessOpeningMode::Joint] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(
                serde_json::from_str::<WitnessOpeningMode>(&json).unwrap(),
                mode
            );
            let postcard = postcard::to_allocvec(&mode).unwrap();
            assert_eq!(
                postcard::from_bytes::<WitnessOpeningMode>(&postcard).unwrap(),
                mode
            );
        }
    }
}
