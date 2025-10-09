use {
    crate::witness::witness_builder::WitnessBuilderSolver,
    acir::native_types::WitnessMap,
    anyhow::{ensure, Result},
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::batch_inverse_montgomery,
        witness::{LayerType, LayeredWitnessBuilders, WitnessBuilder},
        FieldElement, NoirElement, R1CS,
    },
    spongefish::ProverState,
    tracing::instrument,
};

pub trait R1CSSolver {
    fn solve_witness_vec(
        &self,
        plan: LayeredWitnessBuilders,
        acir_map: WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> Vec<Option<FieldElement>>;

    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> Result<()>;
}

impl R1CSSolver for R1CS {
    /// Solves the R1CS witness vector using layered execution with batch
    /// inversion.
    ///
    /// Executes witness builders in segments: each segment consists of a PRE
    /// phase (non-inverse operations) followed by a batch inversion phase.
    /// This approach minimizes expensive field inversions by batching them
    /// using Montgomery's trick.
    ///
    /// # Algorithm
    ///
    /// For each segment:
    /// 1. Execute all PRE builders (non-inverse operations) serially
    /// 2. Collect denominators from pending inverse operations
    /// 3. Perform batch inversion using Montgomery's algorithm
    /// 4. Write inverse results to witness vector
    ///
    /// # Panics
    ///
    /// Panics if a denominator witness is not set when needed for inversion.
    /// This indicates a bug in the layer scheduling algorithm.
    #[instrument(skip_all)]
    fn solve_witness_vec(
        &self,
        plan: LayeredWitnessBuilders,
        acir_map: WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> Vec<Option<FieldElement>> {
        let mut witness = vec![None; self.num_witnesses()];

        for layer in &plan.layers {
            match layer.typ {
                LayerType::Other => {
                    // Execute regular operations
                    for builder in &layer.witness_builders {
                        builder.solve(&acir_map, &mut witness, transcript);
                    }
                }
                LayerType::Inverse => {
                    // Execute inverse batch using Montgomery batch inversion
                    let batch_size = layer.witness_builders.len();
                    let mut output_witnesses = Vec::with_capacity(batch_size);
                    let mut denominators = Vec::with_capacity(batch_size);

                    for inverse_builder in &layer.witness_builders {
                        let WitnessBuilder::Inverse(output_witness, denominator_witness) =
                            inverse_builder
                        else {
                            panic!(
                                "Invalid builder in inverse batch: expected Inverse, got {:?}",
                                inverse_builder
                            );
                        };

                        output_witnesses.push(*output_witness);

                        let denominator = witness[*denominator_witness].unwrap_or_else(|| {
                            panic!(
                                "Denominator witness {} not set before inverse operation",
                                denominator_witness
                            )
                        });
                        denominators.push(denominator);
                    }

                    // Perform batch inversion and write results
                    let inverses = batch_inverse_montgomery(&denominators);
                    for (output_witness, inverse_value) in
                        output_witnesses.into_iter().zip(inverses)
                    {
                        witness[output_witness] = Some(inverse_value);
                    }
                }
            }
        }

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
