use {
    super::Command, anyhow::{Context, Result}, argh::FromArgs, mavros_artifacts::R1CS as MavrosR1CS, provekit_common::{
        FieldElement, HashConfig, NoirProofScheme, Prover, R1CS, TranscriptSponge, Verifier, WhirConfig, file::write, utils::next_power_of_two
    }, provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler}, provekit_spark::{SPARKWHIRConfigs, SerializableSparkWitnesses, SparkCommitments, SparkWitnesses, prover::new_whir_config_for_size, types::{COOMatrix, SerializableCommitment, SparkMatrix, TimeStamps}}, std::{
        path::{Path, PathBuf},
        str::FromStr,
    }, tracing::instrument, whir::{hash::Hash, transcript::{DomainSeparator, ProverState, VerifierMessage, VerifierState, codecs::Empty}},
};

#[derive(PartialEq, Eq, Debug)]
enum Compiler {
    Noir,
    Mavros,
}

impl argh::FromArgValue for Compiler {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "noir" => Ok(Compiler::Noir),
            "mavros" => Ok(Compiler::Mavros),
            other => Err(format!(
                "Unknown compiler: {other}. Use \"noir\" or \"mavros\"."
            )),
        }
    }
}

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct Args {
    /// path to the compiled Noir program (noir) or basic artifacts JSON
    /// (mavros)
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the R1CS file (required for mavros compiler)
    #[argh(option, long = "r1cs")]
    r1cs_path: Option<PathBuf>,

    /// compiler backend to use: "noir" (default) or "mavros"
    #[argh(option, long = "compiler", default = "Compiler::Noir")]
    compiler: Compiler,

    /// output path for the prepared proof scheme
    #[argh(
        option,
        long = "pkp",
        short = 'p',
        default = "PathBuf::from(\"noir_proof_scheme.pkp\")"
    )]
    pkp_path: PathBuf,

    /// output path for the verifier
    #[argh(
        option,
        long = "pkv",
        short = 'v',
        default = "PathBuf::from(\"noir_proof_scheme.pkv\")"
    )]
    pkv_path: PathBuf,

    /// output path for the spark R1CS matrix
    #[argh(
        option,
        long = "spark-r1cs",
        default = "PathBuf::from(\"spark_r1cs.bin\")"
    )]
    spark_r1cs_path: PathBuf,

    /// output path for the spark witnesses
    #[argh(
        option,
        long = "spark-witnesses",
        default = "PathBuf::from(\"spark_witnesses.bin\")"
    )]
    spark_witnesses_path: PathBuf,

    /// output path for the spark commitments
    #[argh(
        option,
        long = "spark-commitments",
        default = "PathBuf::from(\"spark_commitments.bin\")"
    )]
    spark_commitments_path: PathBuf,

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_config = HashConfig::from_str(&self.hash).map_err(|e| anyhow::anyhow!("{}", e))?;
        let scheme = match self.compiler {
            Compiler::Noir => NoirCompiler::from_file(&self.program_path, hash_config)
                .context("while compiling Noir program")?,
            Compiler::Mavros => {
                let r1cs_path = self
                    .r1cs_path
                    .as_ref()
                    .context("--r1cs is required when using the mavros compiler")?;
                MavrosCompiler::compile(&self.program_path, r1cs_path, hash_config)
                    .context("while compiling with Mavros")?
            }
        };

        let whir_r1cs_scheme = match &scheme {
            NoirProofScheme::Noir(scheme) => scheme.whir_for_witness.clone(),
            NoirProofScheme::Mavros(scheme) => scheme.whir_for_witness.clone(),
        };

        let spark_r1cs = match &scheme {
            NoirProofScheme::Noir(noir) => build_spark_r1cs_noir(
                &noir.r1cs,
                whir_r1cs_scheme.m_0,
                whir_r1cs_scheme.m,
                whir_r1cs_scheme.w1_size,
                whir_r1cs_scheme.num_challenges,
            )?,
            NoirProofScheme::Mavros(_) => {
                let r1cs_path = self
                    .r1cs_path
                    .as_ref()
                    .context("--r1cs is required when using the mavros compiler")?;

                build_spark_r1cs_mavros(
                    r1cs_path,
                    whir_r1cs_scheme.m_0,
                    whir_r1cs_scheme.m,
                    whir_r1cs_scheme.w1_size,
                    whir_r1cs_scheme.num_challenges,
                )?
            }
        };  

        let num_rows = spark_r1cs.timestamps.final_row.len();
        let num_cols = spark_r1cs.timestamps.final_col.len();
        let num_nz_vals = spark_r1cs.coo.val.len();

        provekit_common::register_ntt();
        let spark_committer_scheme = SPARKCommitterScheme::new(num_rows, num_cols, num_nz_vals);
        let ds = DomainSeparator::protocol(&spark_committer_scheme.whir_configs).instance(&Empty);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::default());
        let witnesses = spark_committer_scheme.commit(&mut merlin, &spark_r1cs);

        let spark_r1cs_bytes =
            postcard::to_stdvec(&spark_r1cs).context("while serializing spark R1CS")?;
        std::fs::write(&self.spark_r1cs_path, spark_r1cs_bytes)
            .context("while writing spark R1CS")?;

        let serializable_witnesses = SerializableSparkWitnesses::from(witnesses);
        let spark_witnesses_bytes =
            postcard::to_stdvec(&serializable_witnesses).context("while serializing spark witnesses")?;
        std::fs::write(&self.spark_witnesses_path, spark_witnesses_bytes)
            .context("while writing spark witnesses")?;
  
        let proof = merlin.proof();
        let mut arthur = VerifierState::new(&ds, &proof, TranscriptSponge::default());
        let commitments = extract_commitments(&mut arthur, &spark_committer_scheme.whir_configs)?;
        let spark_commitments_bytes =
            postcard::to_stdvec(&commitments).context("while serializing spark commitments")?;
        std::fs::write(&self.spark_commitments_path, spark_commitments_bytes)
            .context("while writing spark commitments")?;

        let prover = Prover::from_noir_proof_scheme(scheme.clone());
        let verifier = Verifier::from_noir_proof_scheme(scheme);

        write(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
        write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
        Ok(())
    }
}

fn build_spark_r1cs_noir(
    r1cs: &R1CS,
    log_row: usize,
    log_col: usize,
    w1_size: usize,
    num_challenges: usize,
) -> Result<SparkMatrix> {
    let is_single_commitment = num_challenges == 0;

    let original_num_entries =
        r1cs.a().iter().count() + r1cs.b().iter().count() + r1cs.c().iter().count();

    let padded_num_entries = 1 << next_power_of_two(original_num_entries);
    let to_fill = padded_num_entries - original_num_entries;

    let row_cnt = 1 << log_row;
    let col_cnt = if is_single_commitment {
        1 << log_col
    } else {
        1 << (1 + log_col)
    };

    let col_witness_split_offset = |c: usize| -> usize {
        if !is_single_commitment && (c >= w1_size) {
            (1 << log_col) - w1_size
        } else {
            0
        }
    };

    let (mut row, mut col, mut val) = (
        Vec::with_capacity(padded_num_entries),
        Vec::with_capacity(padded_num_entries),
        Vec::with_capacity(padded_num_entries),
    );

    for (matrix, row_offset, col_offset) in [
        (r1cs.a(), 0, 0),
        (r1cs.b(), 0, col_cnt),
        (r1cs.c(), row_cnt, col_cnt),
    ] {
        for ((r, c), v) in matrix.iter() {
            row.push(r + row_offset);
            col.push(c + col_offset + col_witness_split_offset(c));
            val.push(v);
        }
    }
    for _ in 0..to_fill {
        row.push(0);
        col.push(0);
        val.push(FieldElement::from(0u64));
    }

    Ok(build_spark_matrix(row, col, val, 2 * row_cnt, 2 * col_cnt))
}

fn build_spark_r1cs_mavros(
    r1cs_path: &Path,
    log_row: usize,
    log_col: usize,
    w1_size: usize,
    num_challenges: usize,
) -> Result<SparkMatrix> {
    let is_single_commitment = num_challenges == 0;

    let r1cs_bytes = std::fs::read(r1cs_path).context("while reading R1CS file")?;
    let r1cs: MavrosR1CS =
        bincode::deserialize(&r1cs_bytes).context("while deserializing R1CS from bincode")?;

    let row_cnt = 1 << log_row;
    let col_cnt = if is_single_commitment {
        1 << log_col
    } else {
        1 << (1 + log_col)
    };

    let col_witness_split_offset = |c: usize| -> usize {
        if !is_single_commitment && (c >= w1_size) {
            (1 << log_col) - w1_size
        } else {
            0
        }
    };

    let original_num_entries: usize = r1cs
        .constraints
        .iter()
        .map(|r1c| r1c.a.len() + r1c.b.len() + r1c.c.len())
        .sum();

    let padded_num_entries = 1 << next_power_of_two(original_num_entries);
    let to_fill = padded_num_entries - original_num_entries;

    let (mut row, mut col, mut val) = (
        Vec::with_capacity(padded_num_entries),
        Vec::with_capacity(padded_num_entries),
        Vec::with_capacity(padded_num_entries),
    );

    for (i, r1c) in r1cs.constraints.iter().enumerate() {
        for &(c, v) in &r1c.a {
            row.push(i);
            col.push(c + col_witness_split_offset(c));
            val.push(v);
        }
        for &(c, v) in &r1c.b {
            row.push(i);
            col.push(c + col_cnt + col_witness_split_offset(c));
            val.push(v);
        }
        for &(c, v) in &r1c.c {
            row.push(i + row_cnt);
            col.push(c + col_cnt + col_witness_split_offset(c));
            val.push(v);
        }
    }

    for _ in 0..to_fill {
        row.push(0);
        col.push(0);
        val.push(FieldElement::from(0u64));
    }

    Ok(build_spark_matrix(row, col, val, 2 * row_cnt, 2 * col_cnt))
}

fn build_spark_matrix(
    row: Vec<usize>,
    col: Vec<usize>,
    val: Vec<FieldElement>,
    num_rows: usize,
    num_cols: usize,
) -> SparkMatrix {
    let len = row.len();
    let mut read_row_counters = vec![0usize; num_rows];
    let mut read_col_counters = vec![0usize; num_cols];
    let mut read_row = Vec::with_capacity(len);
    let mut read_col = Vec::with_capacity(len);

    for i in 0..len {
        read_row.push(FieldElement::from(read_row_counters[row[i]] as u64));
        read_row_counters[row[i]] += 1;
        read_col.push(FieldElement::from(read_col_counters[col[i]] as u64));
        read_col_counters[col[i]] += 1;
    }

    let final_row = read_row_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect();
    let final_col = read_col_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect();

    SparkMatrix {
        coo:        COOMatrix { row, col, val },
        timestamps: TimeStamps {
            read_row,
            read_col,
            final_row,
            final_col,
        },
    }
}

pub struct SPARKCommitterScheme {
    pub whir_configs:      SPARKWHIRConfigs,
}

impl SPARKCommitterScheme {
    pub fn new(num_rows: usize, num_cols: usize, nonzero_terms: usize) -> Self {
        let padded_num_entries = 1 << next_power_of_two(nonzero_terms);

        let row_config = new_whir_config_for_size(next_power_of_two(num_rows), 1);
        let col_config = new_whir_config_for_size(next_power_of_two(num_cols), 1);
        let num_terms_1batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 1);
        let num_terms_2batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 2);
        let num_terms_4batched_config =
            new_whir_config_for_size(next_power_of_two(padded_num_entries), 4);

        Self {
            whir_configs:      SPARKWHIRConfigs {
                row:                row_config,
                col:                col_config,
                num_terms_1batched: num_terms_1batched_config,
                num_terms_2batched: num_terms_2batched_config,
                num_terms_4batched: num_terms_4batched_config,
            },
        }
    }

    pub fn commit(&self, merlin: &mut ProverState<TranscriptSponge>, matrix: &SparkMatrix) -> SparkWitnesses {
        let vals_witness = self.whir_configs.num_terms_1batched.commit(merlin, &[&matrix.coo.val]);

        let row_field: Vec<FieldElement> = matrix
            .coo
            .row
            .iter()
            .map(|&r| FieldElement::from(r as u64))
            .collect();
        let col_field: Vec<FieldElement> = matrix
            .coo
            .col
            .iter()
            .map(|&c| FieldElement::from(c as u64))
            .collect();

        let rs_ws_witness = self.whir_configs.num_terms_4batched.commit(merlin, &[
            &row_field,
            &matrix.timestamps.read_row,
            &col_field,
            &matrix.timestamps.read_col,
        ]);

        let final_row_ts_witness = self.whir_configs
            .row
            .commit(merlin, &[&matrix.timestamps.final_row]);

        let final_col_ts_witness = self.whir_configs
            .col
            .commit(merlin, &[&matrix.timestamps.final_col]);
        
        SparkWitnesses {
            vals_witness,
            rs_ws_witness,
            final_row_ts_witness,
            final_col_ts_witness,
        }
    }
}

fn extract_single_commitment(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    config: &WhirConfig,
) -> Result<SerializableCommitment> {
    let ic = &config.initial_committer;
    let merkle_root: Hash = arthur
        .prover_message()
        .map_err(|e| anyhow::anyhow!("Failed to read merkle root: {e}"))?;
    let out_of_domain_points: Vec<FieldElement> =
        arthur.verifier_message_vec(ic.out_domain_samples);
    let out_of_domain_evals: Vec<FieldElement> = arthur
        .prover_messages_vec(ic.out_domain_samples * ic.num_vectors)
        .map_err(|e| anyhow::anyhow!("Failed to read OOD evaluations: {e}"))?;
    Ok(SerializableCommitment {
        merkle_root,
        out_of_domain_points,
        out_of_domain_evals,
    })
}

fn extract_commitments(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    configs: &SPARKWHIRConfigs,
) -> Result<SparkCommitments> {
    let vals = extract_single_commitment(arthur, &configs.num_terms_1batched)
        .context("while extracting vals commitment")?;
    let rs_ws = extract_single_commitment(arthur, &configs.num_terms_4batched)
        .context("while extracting rs_ws commitment")?;
    let final_row_ts = extract_single_commitment(arthur, &configs.row)
        .context("while extracting final_row_ts commitment")?;
    let final_col_ts = extract_single_commitment(arthur, &configs.col)
        .context("while extracting final_col_ts commitment")?;
    Ok(SparkCommitments {
        vals,
        rs_ws,
        final_row_ts,
        final_col_ts,
    })
}

