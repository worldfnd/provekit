use {
    crate::witness::witness_builder::WitnessBuilderSolver,
    acir::native_types::WitnessMap,
    provekit_common::{
        utils::batch_inverse_montgomery,
        witness::{LayerType, LayeredWitnessBuilders, WitnessBuilder},
        FieldElement, NoirElement, TranscriptSponge, R1CS,
    },
    tracing::instrument,
    whir::transcript::ProverState,
};

/// Serialized R1CS matrices held as a compact postcard blob.
///
/// The R1CS is only needed during the sumcheck phase. Compressing it
/// into a serialized blob frees that memory during the commit phase,
/// then decompresses when the sumcheck begins.
pub struct CompressedR1CS {
    num_constraints: usize,
    num_witnesses:   usize,
    blob:            Vec<u8>,
}

/// Serialized witness builder layers held as a compact postcard blob.
///
/// Same strategy as [`CompressedR1CS`]: the w2 layers are not needed
/// until challenge-dependent witness solving, so we compress them to
/// free memory during the w1 commit.
pub struct CompressedLayers {
    blob: Vec<u8>,
}

impl CompressedLayers {
    #[must_use]
    pub fn compress(layers: LayeredWitnessBuilders) -> Self {
        let blob =
            postcard::to_allocvec(&layers).expect("LayeredWitnessBuilders serialization failed");
        Self { blob }
    }

    #[must_use]
    pub fn decompress(self) -> LayeredWitnessBuilders {
        postcard::from_bytes(&self.blob).expect("LayeredWitnessBuilders deserialization failed")
    }
}

impl CompressedR1CS {
    #[must_use]
    pub fn compress(r1cs: R1CS) -> Self {
        let num_constraints = r1cs.num_constraints();
        let num_witnesses = r1cs.num_witnesses();
        let blob = postcard::to_allocvec(&r1cs).expect("R1CS serialization failed");
        drop(r1cs);
        Self {
            num_constraints,
            num_witnesses,
            blob,
        }
    }

    #[must_use]
    pub fn decompress(self) -> R1CS {
        postcard::from_bytes(&self.blob).expect("R1CS deserialization failed")
    }

    pub const fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    pub const fn num_witnesses(&self) -> usize {
        self.num_witnesses
    }

    pub fn blob_len(&self) -> usize {
        self.blob.len()
    }
}

#[cfg(test)]
pub trait R1CSSolver {
    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> anyhow::Result<()>;
}

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
pub fn solve_witness_vec(
    witness: &mut Vec<Option<FieldElement>>,
    plan: LayeredWitnessBuilders,
    acir_map: &WitnessMap<NoirElement>,
    transcript: &mut ProverState<TranscriptSponge>,
) {
    for layer in &plan.layers {
        match layer.typ {
            LayerType::Other => {
                // Execute regular operations
                for builder in &layer.witness_builders {
                    builder.solve(acir_map, witness, transcript);
                }
            }
            LayerType::Inverse => {
                // Execute inverse batch using Montgomery batch inversion
                let batch_size = layer.witness_builders.len();
                let mut output_witnesses = Vec::with_capacity(batch_size);
                let mut denominators = Vec::with_capacity(batch_size);
                // Optional post-multiply: for quotient builders,
                // result = inverse * multiplicity instead of bare
                // inverse.
                let mut multipliers: Vec<Option<usize>> = Vec::with_capacity(batch_size);

                for inverse_builder in &layer.witness_builders {
                    match inverse_builder {
                        WitnessBuilder::Inverse(output_witness, denominator_witness) => {
                            output_witnesses.push(*output_witness);
                            let denominator = witness[*denominator_witness].unwrap_or_else(|| {
                                panic!(
                                    "Denominator witness {} not set before inverse operation",
                                    denominator_witness
                                )
                            });
                            denominators.push(denominator);
                            multipliers.push(None);
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
                            multipliers.push(None);
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
                            multipliers.push(None);
                        }
                        WitnessBuilder::SpreadTableQuotient {
                            idx,
                            sz,
                            rs,
                            input_val,
                            spread_val,
                            multiplicity,
                        } => {
                            output_witnesses.push(*idx);
                            // Compute denominator: sz - input_val - rs * spread_val
                            let sz_val = witness[*sz].unwrap();
                            let rs_val = witness[*rs].unwrap();
                            let denominator = sz_val - *input_val - (rs_val * *spread_val);
                            denominators.push(denominator);
                            multipliers.push(Some(*multiplicity));
                        }
                        _ => {
                            panic!(
                                "Invalid builder in inverse batch: expected Inverse, \
                                 LogUpInverse, CombinedTableEntryInverse, or SpreadTableQuotient, \
                                 got {:?}",
                                inverse_builder
                            );
                        }
                    }
                }

                // Perform batch inversion and write results
                let inverses = batch_inverse_montgomery(&denominators);
                for ((output_witness, inverse_value), multiplier) in
                    output_witnesses.into_iter().zip(inverses).zip(multipliers)
                {
                    witness[output_witness] = Some(match multiplier {
                        Some(m) => inverse_value * witness[m].unwrap(),
                        None => inverse_value,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
impl R1CSSolver for R1CS {
    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    #[instrument(skip_all, fields(size = witness.len()))]
    fn test_witness_satisfaction(&self, witness: &[FieldElement]) -> anyhow::Result<()> {
        use anyhow::ensure;

        ensure!(
            witness.len() == self.num_witnesses(),
            "Witness size does not match"
        );

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a_val, b_val), c_val)) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(c.into_iter())
            .enumerate()
        {
            ensure!(a_val * b_val == c_val, "Constraint {row} failed");
        }
        Ok(())
    }
}
