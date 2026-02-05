#[cfg(test)]
use anyhow::{ensure, Result};
use {
    crate::witness::witness_builder::WitnessBuilderSolver,
    acir::native_types::WitnessMap,
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
        witness: &mut Vec<Option<FieldElement>>,
        plan: LayeredWitnessBuilders,
        acir_map: &WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    );

    #[cfg(test)]
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
        witness: &mut Vec<Option<FieldElement>>,
        plan: LayeredWitnessBuilders,
        acir_map: &WitnessMap<NoirElement>,
        transcript: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) {
        for layer in &plan.layers {
            match layer.typ {
                LayerType::Other => {
                    // Execute regular operations
                    for builder in &layer.witness_builders {
                        builder.solve(&acir_map, witness, transcript);
                    }
                }
                LayerType::Inverse => {
                    // Execute inverse batch using Montgomery batch inversion
                    let batch_size = layer.witness_builders.len();
                    let mut output_witnesses = Vec::with_capacity(batch_size);
                    let mut denominators = Vec::with_capacity(batch_size);

                    for inverse_builder in &layer.witness_builders {
                        match inverse_builder {
                            WitnessBuilder::Inverse(output_witness, denominator_witness) => {
                                output_witnesses.push(*output_witness);
                                let denominator =
                                    witness[*denominator_witness].unwrap_or_else(|| {
                                        panic!(
                                            "Denominator witness {} not set before inverse \
                                             operation",
                                            denominator_witness
                                        )
                                    });
                                denominators.push(denominator);
                            }
                            WitnessBuilder::LogUpInverse(
                                output_witness,
                                sz_challenge,
                                provekit_common::witness::WitnessCoefficient(coeff, value_witness),
                            ) => {
                                output_witnesses.push(*output_witness);
                                // Compute denominator inline: sz - coeff * value
                                let sz = witness[*sz_challenge].unwrap();
                                let value = witness[*value_witness].unwrap();
                                let denominator = sz - (*coeff * value);
                                denominators.push(denominator);
                            }
                            WitnessBuilder::CombinedTableEntryInverse(data) => {
                                output_witnesses.push(data.idx);
                                // Compute denominator inline:
                                // sz - lhs - rs*rhs - rs²*and_out - rs³*xor_out
                                let sz = witness[data.sz_challenge].unwrap();
                                let rs = witness[data.rs_challenge].unwrap();
                                let rs_sqrd = witness[data.rs_sqrd].unwrap();
                                let rs_cubed = witness[data.rs_cubed].unwrap();
                                let denominator = sz
                                    - data.lhs
                                    - (rs * data.rhs)
                                    - (rs_sqrd * data.and_out)
                                    - (rs_cubed * data.xor_out);
                                denominators.push(denominator);
                            }
                            _ => {
                                panic!(
                                    "Invalid builder in inverse batch: expected Inverse, \
                                     LogUpInverse, or CombinedTableEntryInverse, got {:?}",
                                    inverse_builder
                                );
                            }
                        }
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
    }

    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    #[cfg(test)]
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
