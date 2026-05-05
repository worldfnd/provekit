use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    mavros_artifacts::R1CS as MavrosR1CS,
    provekit_common::{
        file::write, utils::next_power_of_two, FieldElement, HashConfig, NoirProofScheme, Prover,
        Verifier, R1CS,
    },
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    provekit_spark::types::{COOMatrix, SparkMatrix, TimeStamps},
    std::{
        path::{Path, PathBuf},
        str::FromStr,
    },
    tracing::{info, instrument},
};

#[derive(PartialEq, Eq, Debug)]
pub enum Compiler {
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

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3, poseidon2)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,

    /// also run SPARK preprocessing and write the SPARK setup transcript
    #[argh(switch, long = "spark")]
    spark: bool,

    /// output path for the SPARK setup transcript (used with --spark)
    #[argh(
        option,
        long = "spc",
        default = "PathBuf::from(\"noir_proof_scheme.spc\")"
    )]
    spc_path: PathBuf,
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

        if self.spark {
            provekit_common::register_ntt();
            let matrix = build_spark_matrix_for_scheme(&scheme, self.r1cs_path.as_deref())?;
            let (setup, _witnesses) = provekit_spark::preprocess_spark(&matrix, hash_config);
            write(&setup, &self.spc_path)
                .with_context(|| format!("writing SPARK setup to {:?}", self.spc_path))?;
            info!("Wrote SPARK setup to {:?}", self.spc_path);
        }

        let prover = Prover::from_noir_proof_scheme(scheme.clone());
        let verifier = Verifier::from_noir_proof_scheme(scheme);

        write(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
        write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
        Ok(())
    }
}

pub fn build_spark_matrix_for_scheme(
    scheme: &NoirProofScheme,
    r1cs_path: Option<&Path>,
) -> Result<SparkMatrix> {
    let whir = match scheme {
        NoirProofScheme::Noir(s) => s.whir_for_witness.clone(),
        NoirProofScheme::Mavros(s) => s.whir_for_witness.clone(),
    };
    match scheme {
        NoirProofScheme::Noir(noir) => build_spark_r1cs_noir(
            &noir.r1cs,
            whir.m_0,
            whir.m,
            whir.w1_size,
            whir.num_challenges,
        ),
        NoirProofScheme::Mavros(_) => {
            let r1cs_path =
                r1cs_path.context("--r1cs is required for SPARK with the mavros compiler")?;
            build_spark_r1cs_mavros(
                r1cs_path,
                whir.m_0,
                whir.m,
                whir.w1_size,
                whir.num_challenges,
            )
        }
    }
}

pub fn build_spark_r1cs_noir(
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

pub fn build_spark_r1cs_mavros(
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

pub fn build_spark_matrix(
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

    let row_field = row.iter().map(|&r| FieldElement::from(r as u64)).collect();
    let col_field = col.iter().map(|&c| FieldElement::from(c as u64)).collect();

    SparkMatrix {
        coo:        COOMatrix {
            row,
            col,
            row_field,
            col_field,
            val,
        },
        timestamps: TimeStamps {
            read_row,
            read_col,
            final_row,
            final_col,
        },
    }
}
