use {
    crate::r1cs::R1CSSolver,
    acir::native_types::WitnessMap,
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    provekit_common::{
        blake3::{Blake3MerkleConfig, Blake3PoW},
        keccak::{KeccakMerkleConfig, KeccakPoW},
        sha256::{Sha256MerkleConfig, Sha256PoW},
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW},
        FieldElement, NoirElement, NoirProof, Prover, WhirDomainSep, WhirMerkleConfig,
        WhirProverState,
    },
    spongefish::{DomainSeparator, ProverState},
    std::path::Path,
    tracing::instrument,
};

mod r1cs;
mod whir_r1cs;
mod witness;

pub trait Prove {
    fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>>;

    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;
}

// Helper function for witness generation (shared across all implementations)
fn generate_witness_internal<MerkleConfig, PowStrategy>(
    prover: &mut Prover<MerkleConfig, PowStrategy>,
    input_map: InputMap,
) -> Result<WitnessMap<NoirElement>>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
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

    let initial_witness = prover.witness_generator.abi().encode(&input_map, None)?;

    let mut witness_stack = nargo::ops::execute_program(
        &prover.program,
        initial_witness,
        &solver,
        &mut foreign_call_executor,
    )?;

    Ok(witness_stack
        .pop()
        .context("Missing witness results")?
        .witness)
}

/// Macro to implement `Prove` for each hash configuration.
/// This generates monomorphized implementations for optimal performance.
macro_rules! impl_prove {
    ($merkle:ty, $pow:ty) => {
        impl Prove for Prover<$merkle, $pow> {
            #[instrument(skip_all)]
            fn generate_witness(&mut self, input_map: InputMap) -> Result<WitnessMap<NoirElement>> {
                generate_witness_internal(self, input_map)
            }

            #[instrument(skip_all)]
            fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
                prove_with_hash(self, prover_toml)
            }
        }
    };
}

impl_prove!(SkyscraperMerkleConfig, SkyscraperPoW);
impl_prove!(Sha256MerkleConfig, Sha256PoW);
impl_prove!(KeccakMerkleConfig, KeccakPoW);
impl_prove!(Blake3MerkleConfig, Blake3PoW);

/// Generates a proof for a Noir program.
#[instrument(skip_all)]
fn prove_with_hash<MerkleConfig, PowStrategy>(
    mut prover: Prover<MerkleConfig, PowStrategy>,
    prover_toml: impl AsRef<Path>,
) -> Result<NoirProof>
where
    MerkleConfig: WhirMerkleConfig,
    PowStrategy: Clone + spongefish_pow::PowStrategy,
    ProverState<MerkleConfig::Sponge, MerkleConfig::Unit>: WhirProverState<MerkleConfig>,
    DomainSeparator<MerkleConfig::Sponge, MerkleConfig::Unit>: WhirDomainSep<MerkleConfig>,
{
    let (input_map, _expected_return) =
        read_inputs_from_file(prover_toml.as_ref(), prover.witness_generator.abi())?;

    let acir_witness_idx_to_value_map = generate_witness_internal(&mut prover, input_map)?;

    // Set up Fiat-Shamir transcript
    let io = prover.whir_for_witness.create_generic_io_pattern();
    let mut merlin = io.to_prover_state();
    drop(io);

    let mut witness: Vec<Option<FieldElement>> = vec![None; prover.r1cs.num_witnesses()];

    // Solve witness values
    prover.r1cs.solve_witness_vec(
        &mut witness,
        prover.split_witness_builders.w1_layers,
        &acir_witness_idx_to_value_map,
        &mut merlin,
    );

    let w1 = witness[..prover.whir_for_witness.w1_size]
        .iter()
        .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w1 are missing")))
        .collect::<Result<Vec<_>>>()?;

    let commitment_1 =
        whir_r1cs::commit::<MerkleConfig::Sponge, MerkleConfig::Unit, MerkleConfig, PowStrategy>(
            &prover.whir_for_witness,
            &mut merlin,
            &prover.r1cs,
            w1,
            true,
        )
        .context("While committing to w1")?;

    // Build commitment list based on whether we have challenges
    let commitments = if prover.whir_for_witness.num_challenges > 0 {
        // Solve w2 - using same sponge
        prover.r1cs.solve_witness_vec(
            &mut witness,
            prover.split_witness_builders.w2_layers,
            &acir_witness_idx_to_value_map,
            &mut merlin,
        );

        let w2 = witness[prover.whir_for_witness.w1_size..]
            .iter()
            .map(|w| w.ok_or_else(|| anyhow::anyhow!("Some witnesses in w2 are missing")))
            .collect::<Result<Vec<_>>>()?;

        let commitment_2 = whir_r1cs::commit::<
            MerkleConfig::Sponge,
            MerkleConfig::Unit,
            MerkleConfig,
            PowStrategy,
        >(
            &prover.whir_for_witness,
            &mut merlin,
            &prover.r1cs,
            w2,
            false,
        )
        .context("While committing to w2")?;

        vec![commitment_1, commitment_2]
    } else {
        vec![commitment_1]
    };
    drop(acir_witness_idx_to_value_map);

    #[cfg(test)]
    prover
        .r1cs
        .test_witness_satisfaction(&witness.iter().map(|w| w.unwrap()).collect::<Vec<_>>())
        .context("While verifying R1CS instance")?;
    drop(witness);

    let whir_r1cs_proof = whir_r1cs::prove::<
        MerkleConfig::Sponge,
        MerkleConfig::Unit,
        MerkleConfig,
        PowStrategy,
    >(&prover.whir_for_witness, merlin, prover.r1cs, commitments)
    .context("While proving R1CS instance")?;

    Ok(NoirProof { whir_r1cs_proof })
}

#[cfg(test)]
mod tests {}
