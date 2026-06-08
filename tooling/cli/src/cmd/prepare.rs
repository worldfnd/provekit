use {
    super::{util::resolve_key_path, Command},
    anyhow::{anyhow, bail, Context as _, Result},
    argh::FromArgs,
    mavros_artifacts::R1CS as MavrosR1CS,
    nargo::{
        insert_all_files_for_workspace_into_file_manager,
        ops::{check_program, collect_errors, compile_program, optimize_program, report_errors},
        parse_all,
    },
    nargo_toml::{find_root, get_package_manifest, resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::fs::artifact::save_program_to_file,
    noirc_driver::{CompilationResult, CompileOptions, CrateName, NOIR_ARTIFACT_VERSION_STRING},
    provekit_common::{
        file::write, utils::next_power_of_two, FieldElement, HashConfig, NoirProofScheme, Prover,
        Verifier, R1CS,
    },
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    provekit_spark::types::SparkMatrix,
    rayon::prelude::*,
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

/// Compile a Noir program and build its prover and verifier keys.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct Args {
    /// directory containing Nargo.toml for noir, or path to the basic
    /// artifacts JSON for mavros (default: current directory)
    #[argh(positional, default = "PathBuf::from(\".\")")]
    program_path: PathBuf,

    /// path to the R1CS file (required for mavros compiler)
    #[argh(option, long = "r1cs")]
    r1cs_path: Option<PathBuf>,

    /// compiler backend to use: "noir" (default) or "mavros"
    #[argh(option, long = "compiler", default = "Compiler::Noir")]
    compiler: Compiler,

    /// name of the package to compile (noir only; default: enclosing package)
    #[argh(option)]
    package: Option<String>,

    /// compile every package in the workspace (noir only)
    #[argh(switch)]
    workspace: bool,

    /// override the target directory for compiled artifacts (noir only)
    #[argh(option)]
    target_dir: Option<PathBuf>,

    /// treat warnings as errors (noir only)
    #[argh(switch)]
    deny_warnings: bool,

    /// suppress warnings (noir only)
    #[argh(switch)]
    silence_warnings: bool,

    /// print the ACIR for the compiled circuit (noir only)
    #[argh(switch)]
    print_acir: bool,

    /// skip the under-constrained-values check (noir only)
    #[argh(switch)]
    skip_underconstrained_check: bool,

    /// skip the Brillig call-constraints check (noir only)
    #[argh(switch)]
    skip_brillig_constraints_check: bool,

    /// force a full recompilation, ignoring cached artifacts (noir only)
    #[argh(switch)]
    force: bool,

    /// output path for the ProveKit Prover (PKP) key (default:
    /// `<circuit>.pkp`)
    #[argh(option, long = "pkp", short = 'p')]
    pkp_path: Option<PathBuf>,

    /// output path for the ProveKit Verifier (PKV) key (default:
    /// `<circuit>.pkv`)
    #[argh(option, long = "pkv", short = 'v')]
    pkv_path: Option<PathBuf>,

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

    /// output path for the bundled SPARK prover context — matrix, witnesses
    /// and setup (used with --spark)
    #[argh(
        option,
        long = "spctx",
        default = "PathBuf::from(\"noir_proof_scheme.spctx\")"
    )]
    spctx_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_config = HashConfig::from_str(&self.hash).map_err(|e| anyhow!("{}", e))?;
        match self.compiler {
            Compiler::Noir => self.run_noir(hash_config),
            Compiler::Mavros => self.run_mavros(hash_config),
        }
    }
}

impl Args {
    fn run_noir(&self, hash_config: HashConfig) -> Result<()> {
        // Canonicalize so compiled artifacts embed absolute source paths,
        // matching `nargo compile` byte-for-byte in the `file_map` field.
        let program_dir = std::fs::canonicalize(&self.program_path)
            .with_context(|| format!("canonicalizing {}", self.program_path.display()))?;
        let workspace_dir = find_root(&program_dir, true)?;
        let package_dir = find_root(&program_dir, false)?;

        let selection = self.package_selection(&workspace_dir, &package_dir)?;
        let mut workspace = resolve_workspace_from_toml(
            &get_package_manifest(&workspace_dir)?,
            selection,
            Some(NOIR_ARTIFACT_VERSION_STRING.to_owned()),
        )?;
        workspace.target_dir = self.target_dir.clone();

        let options = self.compile_options();
        let mut file_manager = workspace.new_file_manager();
        insert_all_files_for_workspace_into_file_manager(&workspace, &mut file_manager);
        let parsed_files = parse_all(&file_manager);

        let binary_packages: Vec<_> = workspace
            .into_iter()
            .filter(|p| p.is_binary())
            .cloned()
            .collect();

        if binary_packages.is_empty() {
            bail!("no binary packages found in workspace");
        }
        if binary_packages.len() > 1 && (self.pkp_path.is_some() || self.pkv_path.is_some()) {
            bail!("--pkp/--pkv cannot be used with multiple binary packages");
        }
        if binary_packages.len() > 1 && self.spark {
            bail!("--spark cannot be used with multiple binary packages");
        }

        let target_dir = workspace.target_directory_path();

        let program_results: Vec<CompilationResult<_>> = binary_packages
            .par_iter()
            .map(|package| {
                let (program, warnings) = compile_program(
                    &file_manager,
                    &parsed_files,
                    &workspace,
                    package,
                    &options,
                    None,
                )?;
                let program = optimize_program(program);
                check_program(&program)?;
                let artifact = program.into();
                save_program_to_file(&artifact, &package.name, &target_dir)
                    .expect("saving program artifact");
                Ok((artifact, warnings))
            })
            .collect();

        let artifacts = report_errors(
            collect_errors(program_results),
            &file_manager,
            options.deny_warnings,
            options.silence_warnings,
        )?;

        for (package, artifact) in binary_packages.iter().zip(artifacts) {
            let scheme = NoirCompiler::from_program(artifact, hash_config)
                .context("while building Noir proof scheme")?;
            self.maybe_write_spark(&scheme, hash_config)?;
            let pkp_path = self
                .pkp_path
                .clone()
                .unwrap_or_else(|| format!("{}.pkp", package.name).into());
            let pkv_path = self
                .pkv_path
                .clone()
                .unwrap_or_else(|| format!("{}.pkv", package.name).into());
            write(&Prover::from_noir_proof_scheme(scheme.clone()), &pkp_path)
                .context("while writing prover key")?;
            write(&Verifier::from_noir_proof_scheme(scheme), &pkv_path)
                .context("while writing verifier key")?;
        }
        Ok(())
    }

    fn run_mavros(&self, hash_config: HashConfig) -> Result<()> {
        let r1cs_path = self
            .r1cs_path
            .as_ref()
            .context("--r1cs is required when using the mavros compiler")?;
        let scheme = MavrosCompiler::compile(&self.program_path, r1cs_path, hash_config)
            .context("while compiling with Mavros")?;
        self.maybe_write_spark(&scheme, hash_config)?;
        let pkp_path = resolve_key_path(self.pkp_path.as_deref(), "pkp")?;
        let pkv_path = resolve_key_path(self.pkv_path.as_deref(), "pkv")?;
        write(&Prover::from_noir_proof_scheme(scheme.clone()), &pkp_path)
            .context("while writing prover key")?;
        write(&Verifier::from_noir_proof_scheme(scheme), &pkv_path)
            .context("while writing verifier key")?;
        Ok(())
    }

    fn maybe_write_spark(&self, scheme: &NoirProofScheme, hash_config: HashConfig) -> Result<()> {
        if !self.spark {
            return Ok(());
        }
        provekit_common::register_ntt();
        let matrix = build_spark_matrix_for_scheme(scheme, self.r1cs_path.as_deref())?;
        let (setup, witnesses) = provekit_spark::preprocess_spark(&matrix, hash_config);
        write(&setup, &self.spc_path)
            .with_context(|| format!("writing SPARK setup to {:?}", self.spc_path))?;
        info!("Wrote SPARK setup to {:?}", self.spc_path);
        let context = provekit_spark::SparkProverContext {
            matrix,
            witnesses,
            setup,
        };
        write(&context, &self.spctx_path)
            .with_context(|| format!("writing SPARK prover context to {:?}", self.spctx_path))?;
        info!("Wrote SPARK prover context to {:?}", self.spctx_path);
        Ok(())
    }

    fn compile_options(&self) -> CompileOptions {
        CompileOptions {
            deny_warnings: self.deny_warnings,
            silence_warnings: self.silence_warnings,
            print_acir: self.print_acir,
            skip_underconstrained_check: self.skip_underconstrained_check,
            skip_brillig_constraints_check: self.skip_brillig_constraints_check,
            force_compile: self.force,
            ..CompileOptions::default()
        }
    }

    fn package_selection(
        &self,
        workspace_dir: &Path,
        package_dir: &Path,
    ) -> Result<PackageSelection> {
        if self.workspace {
            return Ok(PackageSelection::All);
        }
        if let Some(name) = &self.package {
            let crate_name: CrateName = name
                .parse()
                .map_err(|e| anyhow!("invalid package name `{name}`: {e}"))?;
            return Ok(PackageSelection::Selected(crate_name));
        }
        // When CWD is inside a sub-package of a multi-package workspace, narrow
        // to that package rather than compiling the whole workspace.
        if workspace_dir != package_dir {
            let inner = resolve_workspace_from_toml(
                &get_package_manifest(package_dir)?,
                PackageSelection::DefaultOrAll,
                Some(NOIR_ARTIFACT_VERSION_STRING.to_owned()),
            )?;
            let package = inner
                .into_iter()
                .next()
                .expect("a package manifest resolves to exactly one member");
            return Ok(PackageSelection::Selected(package.name.clone()));
        }
        Ok(PackageSelection::DefaultOrAll)
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

    Ok(SparkMatrix::new(row, col, val, 2 * row_cnt, 2 * col_cnt))
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

    Ok(SparkMatrix::new(row, col, val, 2 * row_cnt, 2 * col_cnt))
}

