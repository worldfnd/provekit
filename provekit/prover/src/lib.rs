use {
    crate::{
        r1cs::R1CSSolver,
        whir_r1cs::WhirR1CSProver,
        witness::{fill_witness, witness_io_pattern::WitnessIOPattern},
    },
    acir::{circuit::Program, native_types::WitnessMap},
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::noir_to_native,
        witness::{LayeredWitnessBuilders, NoirWitnessGenerator, WitnessBuilder},
        FieldElement, IOPattern, NoirElement, NoirProof, Prover, R1CS,
    },
    spongefish::{codecs::arkworks_algebra::FieldToUnitSerialize, ProverState},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

#[instrument(skip_all)]
fn generate_witness(
    program: &Program<NoirElement>,
    witness_generator: NoirWitnessGenerator,
    input_map: InputMap,
) -> Result<WitnessMap<NoirElement>> {
    let solver = Bn254BlackBoxSolver::default();
    let mut output_buffer = Vec::new();
    let mut foreign_call_executor = DefaultForeignCallBuilder {
        output:       &mut output_buffer,
        enable_mocks: false,
        resolver_url: None,
        root_path:    None,
        package_name: None,
    }
    .build();

    let initial_witness = witness_generator.abi().encode(&input_map, None)?;

    let mut witness_stack = nargo::ops::execute_program(
        program,
        initial_witness,
        &solver,
        &mut foreign_call_executor,
    )?;

    Ok(witness_stack
        .pop()
        .context("Missing witness results")?
        .witness)
}

#[instrument(skip_all)]
pub fn prove(prover: Prover, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
    let program = prover.program;
    let witness_generator = prover.witness_generator;
    let r1cs = prover.r1cs;
    let layered_witness_builders = prover.layered_witness_builders;
    let whir_for_witness = prover.whir_for_witness;

    let (input_map, _expected_return) =
        read_inputs_from_file(prover_toml.as_ref(), witness_generator.abi())?;

    let acir_witness_idx_to_value_map = generate_witness(&program, witness_generator, input_map)?;

    // Solve R1CS instance
    let witness_io = create_witness_io_pattern(&program, &layered_witness_builders);
    let mut witness_merlin = witness_io.to_prover_state();
    seed_witness_merlin(
        program,
        &r1cs,
        &mut witness_merlin,
        &acir_witness_idx_to_value_map,
    )?;

    let partial_witness = r1cs.solve_witness_vec(
        layered_witness_builders,
        acir_witness_idx_to_value_map,
        &mut witness_merlin,
    );
    let witness = fill_witness(partial_witness).context("while filling witness")?;

    // Verify witness (redudant with solve)
    #[cfg(test)]
    r1cs.test_witness_satisfaction(&witness)
        .context("While verifying R1CS instance")?;

    // Prove R1CS instance
    let whir_r1cs_proof = whir_for_witness
        .prove(r1cs, witness)
        .context("While proving R1CS instance")?;

    Ok(NoirProof { whir_r1cs_proof })
}

fn create_witness_io_pattern(
    program: &Program<NoirElement>,
    layered_witness_builders: &LayeredWitnessBuilders,
) -> IOPattern {
    let circuit = &program.functions[0];
    let public_idxs = circuit.public_inputs().indices();
    let num_challenges = layered_witness_builders
        .layers
        .iter()
        .flat_map(|layer| &layer.witness_builders)
        .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
        .count();

    // Create witness IO pattern
    IOPattern::new("📜")
        .add_shape()
        .add_public_inputs(public_idxs.len())
        .add_logup_challenges(num_challenges)
}

fn seed_witness_merlin(
    program: Program<NoirElement>,
    r1cs: &R1CS,
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    witness: &WitnessMap<NoirElement>,
) -> Result<()> {
    // Absorb circuit shape
    let _ = merlin.add_scalars(&[
        FieldElement::from(r1cs.num_constraints() as u64),
        FieldElement::from(r1cs.num_witnesses() as u64),
    ]);

    // Absorb public inputs (values) in canonical order
    let circuit = &program.functions[0];
    let public_idxs = circuit.public_inputs().indices();
    if !public_idxs.is_empty() {
        let pub_vals: Vec<FieldElement> = public_idxs
            .iter()
            .map(|&i| noir_to_native(*witness.get_index(i).expect("missing public input")))
            .collect();
        let _ = merlin.add_scalars(&pub_vals);
    }

    Ok(())
}

#[cfg(test)]
mod tests {}
