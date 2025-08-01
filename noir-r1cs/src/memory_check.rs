use spongefish::{codecs::arkworks_algebra::FieldToUnitSerialize, ProverState};

use crate::{grand_product_argument::GrandProductArgument, skyscraper::{SkyscraperMerkleConfig, SkyscraperSponge}, spark::produce_whir_proof, whir_r1cs::WhirR1CSScheme, FieldElement};
use anyhow::Result;
use crate::whir_r1cs::WhirConfig;
use whir::{poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint}, whir::committer::Witness};
use ark_std::Zero;

pub struct GPAInit {
    variable_count: u64,
    eq:             Vec<FieldElement>,
}

pub trait GPA {
    fn run(
        self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        tau: FieldElement,
        gamma: FieldElement,
    ) -> Result<()>;
}

impl GPA for GPAInit {
    fn run(
        self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        tau: FieldElement,
        gamma: FieldElement,
    ) -> Result<()> {
        GrandProductArgument::new(
            (0..1 << self.variable_count)
                .map(FieldElement::from)
                .collect(),
            self.eq,
            vec![FieldElement::zero(); 1 << self.variable_count],
            tau,
            gamma,
            merlin,
        );

        Ok(())
    }
}