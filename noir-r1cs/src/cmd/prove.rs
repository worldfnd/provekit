use {
    super::{utils::load_noir_program, Command},
    crate::{compiler::R1CS, sparse_matrix::SparseMatrix, witness::generate_witness},
    acir::{circuit::Circuit, native_types::WitnessMap, FieldElement},
    anyhow::{ensure, Context, Result},
    argh::FromArgs,
    ark_ff::{BigInt, PrimeField},
    ark_serialize::CanonicalSerialize as _,
    noir_r1cs::{
        prover::{
            create_io_pattern, run_sumcheck_prover, run_sumcheck_verifier, run_whir_pcs_prover,
            run_whir_pcs_verifier,
        },
        whir_r1cs::{
            skyscraper::{
                skyscraper::SkyscraperSponge, skyscraper_for_whir::SkyscraperMerkleConfig,
                skyscraper_pow::SkyscraperPoW,
            },
            utils::{
                calculate_eq, calculate_external_row_of_r1cs_matrices, gnark_parameters,
                next_power_of_two, pad_to_power_of_two, MatrixCell, R1CS as WhirR1CS,
            },
            whir_utils::{generate_whir_params, Args as WhirArgs},
        },
    },
    noirc_abi::{input_parser::Format, Abi},
    spongefish::{DomainSeparator, ProverState},
    std::{
        fs::File,
        io::Read,
        path::{Path, PathBuf},
    },
    tracing::{info, instrument},
    whir::{
        crypto::fields::Field256,
        parameters::{FoldType, SoundnessType},
        whir::{
            parameters::WhirConfig,
            statement::{Statement, StatementVerifier},
            WhirProof,
        },
    },
};

type Whir = WhirConfig<Field256, SkyscraperMerkleConfig, SkyscraperPoW>;
type WhirSkyProof = WhirProof<SkyscraperMerkleConfig, Field256>;
type IOPattern = DomainSeparator<SkyscraperSponge, Field256>;

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct ProveArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the prepared Noir program
    #[argh(positional)]
    prepared_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,

    // path to store proof file
    #[argh(positional)]
    proof_path: PathBuf,

    // path to store Gnark proof file
    #[argh(positional)]
    gnark_out: PathBuf,
}

impl Command for ProveArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Load Noir circuit for R1CS
        let program = load_noir_program(&self.program_path)?;
        let main = &program.bytecode.functions[0];
        let abi = program.abi;
        let input = read_input(&self.input_path, &abi)?;
        let brillig = program.bytecode.unconstrained_functions;
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );
        let r1cs = prepare_circuit(&main)?;

        // WHIR Configuration
        let (m, m_0, whir_params) = proof_paremeters(&r1cs, WhirArgs {
            security_level:    128,
            pow_bits:          Some(20),
            rate:              1,
            folding_factor:    4,
            soundness_type:    SoundnessType::ConjectureList,
            fold_optimisation: FoldType::ProverHelps,
            input_file_path:   String::new(),
        });

        // Generate the witness vector
        let witness = generate_witness(&r1cs, &brillig, &main, input)?;

        // Convert between ark_ff 0.4.2 and 0.5.0 😢
        let r1cs = convert_r1cs(r1cs);
        let witness = convert_witness_field(witness);

        // Prove the R1CS instance
        let (proof, merlin, whir_params, io, sums, statement, r, alpha, last_sumcheck_val) =
            prove(&r1cs, witness, m, m_0, whir_params);

        // Write proof to file
        write_proof(&proof, &self.proof_path)?;
        write_gnark_params(&whir_params, &merlin, &io, sums, m_0, m, &self.gnark_out)?;

        // Verify proof
        verify(
            whir_params,
            proof,
            &statement,
            &merlin,
            &io,
            sums,
            m_0,
            &r,
            &alpha,
            last_sumcheck_val,
        )
        .context("Verifying proof failed")?;

        Ok(())
    }
}

#[instrument(skip(abi), fields(size = input_path.metadata().map(|m| m.len()).ok()))]
fn read_input(input_path: &Path, abi: &Abi) -> Result<WitnessMap<FieldElement>> {
    let mut file = File::open(input_path).context("while opening input file")?;
    let mut input_string =
        String::with_capacity(file.metadata().map(|m| m.len() as usize).unwrap_or(0));
    file.read_to_string(&mut input_string)
        .context("while reading input file")?;
    let input = Format::Toml
        .parse(&input_string, abi)
        .context("while parsing input file")?;
    let map = abi
        .encode(&input, None)
        .context("while encoding input to witness map")?;
    Ok(map)
}

#[instrument(skip_all, fields(opcodes = circuit.opcodes.len(), witnesses = circuit.current_witness_index))]
fn prepare_circuit(circuit: &Circuit<FieldElement>) -> Result<R1CS> {
    // Create the R1CS relation
    let mut r1cs = R1CS::new();
    r1cs.add_circuit(circuit);
    Ok(r1cs)
}

#[instrument(skip(r1cs), fields(m = r1cs.witnesses, m_0 = r1cs.constraints))]
fn proof_paremeters(r1cs: &R1CS, args: WhirArgs) -> (usize, usize, Whir) {
    // m is equal to ceiling(log(number of variables in constraint system)). It is
    // equal to the log of the width of the matrices.
    let m = next_power_of_two(r1cs.witnesses);
    // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
    // number of variables in the multilinear polynomial we are running our sumcheck
    // on.
    let m_0 = next_power_of_two(r1cs.constraints);
    let whir_params = generate_whir_params(m, args);
    (m, m_0, whir_params)
}

#[instrument(skip_all)]
fn convert_witness_field(witness: Vec<FieldElement>) -> Vec<Field256> {
    witness.into_iter().map(convert_fe).collect()
}

#[instrument(skip_all)]
fn convert_r1cs(r1cs: R1CS) -> WhirR1CS {
    WhirR1CS {
        num_public:      1, // TODO
        num_variables:   r1cs.witnesses,
        num_constraints: r1cs.constraints,
        a:               convert_matrix(r1cs.a),
        b:               convert_matrix(r1cs.b),
        c:               convert_matrix(r1cs.c),
    }
}

#[instrument(skip_all)]
fn convert_matrix(matrix: SparseMatrix<FieldElement>) -> Vec<MatrixCell> {
    matrix
        .iter()
        .map(|((constraint, signal), n)| MatrixCell {
            signal,
            constraint,
            value: convert_fe(*n),
        })
        .collect()
}

fn convert_fe(n: FieldElement) -> Field256 {
    let limbs: [u64; 4] = n.into_repr().0 .0;
    Field256::from_bigint(BigInt(limbs)).unwrap()
}

#[instrument(skip_all)]
fn prove(
    r1cs: &WhirR1CS,
    witness: Vec<Field256>,
    m: usize,
    m_0: usize,
    whir_params: Whir,
) -> (
    WhirSkyProof,
    ProverState<SkyscraperSponge, Field256>,
    Whir,
    IOPattern,
    [Field256; 3],
    Statement<Field256>,
    Vec<Field256>,
    Vec<Field256>,
    Field256,
) {
    let z = pad_to_power_of_two(witness);
    let io = create_io_pattern(m_0, &whir_params);
    let merlin = io.to_prover_state();
    let (merlin, alpha, r, last_sumcheck_val) = run_sumcheck_prover(r1cs, &z, merlin, m_0);
    let alphas = calculate_external_row_of_r1cs_matrices(&alpha, r1cs);
    let (proof, merlin, whir_params, io, whir_query_answer_sums, statement) =
        run_whir_pcs_prover(io, z, whir_params, merlin, m, alphas);

    (
        proof,
        merlin,
        whir_params,
        io,
        whir_query_answer_sums,
        statement,
        r,
        alpha,
        last_sumcheck_val,
    )
}

#[instrument(skip(proof))]
fn write_proof(proof: &WhirSkyProof, output_path: &Path) -> Result<()> {
    // TODO: This is missing the entire transcript.
    let mut file = File::create(output_path).context("while creating output file")?;
    proof
        .serialize_compressed(&mut file)
        .context("while writing output file")?;
    Ok(())
}

#[instrument(skip_all, fields(output_path = ?output_path))]
fn write_gnark_params(
    whir_params: &Whir,
    merlin: &ProverState<SkyscraperSponge, Field256>,
    io: &DomainSeparator<SkyscraperSponge, Field256>,
    sums: [Field256; 3],
    m_0: usize,
    m: usize,
    output_path: &Path,
) -> Result<()> {
    let mut file = File::create(output_path).context("while creating output file")?;
    let gnark_parameters = gnark_parameters(whir_params, merlin, io, sums, m_0, m);
    serde_json::to_writer_pretty(&mut file, &gnark_parameters)
        .context("while writing output file")?;
    Ok(())
}

#[instrument(skip_all)]
fn verify(
    whir_params: Whir,
    proof: WhirSkyProof,
    statement: &Statement<Field256>,
    merlin: &ProverState<SkyscraperSponge, Field256>,
    io: &DomainSeparator<SkyscraperSponge, Field256>,
    whir_query_answer_sums: [Field256; 3],
    m_0: usize,
    r: &[Field256],
    alpha: &[Field256],
    last_sumcheck_val: Field256,
) -> Result<()> {
    let statement_verifier = StatementVerifier::<Field256>::from_statement(statement);

    let arthur = io.to_verifier_state(merlin.narg_string());
    let arthur = run_sumcheck_verifier(m_0, arthur);
    run_whir_pcs_verifier(whir_params, proof, arthur, statement_verifier);
    ensure!(
        last_sumcheck_val
            == (whir_query_answer_sums[0] * whir_query_answer_sums[1] - whir_query_answer_sums[2])
                * calculate_eq(r, alpha),
        "Last sumcheck value does not match"
    );
    Ok(())
}
