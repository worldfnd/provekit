use {
    crate::witness::witness_builder::WitnessBuilderSolver,
    acir::native_types::WitnessMap,
    anyhow::{ensure, Result},
    provekit_common::{
        skyscraper::SkyscraperSponge, witness::WitnessBuilder, FieldElement, NoirElement, R1CS,
    },
    spongefish::ProverState,
    tracing::instrument,
};

pub trait R1CSSolver {
    fn solve_witness_vec(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> Vec<Option<FieldElement>>;

    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> Result<()>;
}

impl R1CSSolver for R1CS {
    fn solve_witness_vec(
        &self,
        witness_builder_vec: &[WitnessBuilder],
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> Vec<Option<FieldElement>> {
        let mut witness = vec![None; self.num_witnesses()];
        witness_builder_vec.iter().for_each(|witness_builder| {
            witness_builder.solve(acir_witness_idx_to_value_map, &mut witness, transcript);
        });

        witness
    }

    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    #[instrument(skip_all, fields(size = witness.len()))]
    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> Result<()> {
        ensure!(
            witness.len() == self.num_witnesses(),
            "Witness size does not match"
        );

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a, b), c)) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(c.into_iter())
            .enumerate()
        {
            ensure!(a * b == c, "Constraint {row} failed");
        }
        Ok(())
    }
}
