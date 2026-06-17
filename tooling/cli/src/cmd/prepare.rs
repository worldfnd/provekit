use {
    super::{util::resolve_key_path, Command},
    anyhow::{anyhow, bail, Context as _, Result},
    argh::FromArgs,
    nargo::{
        insert_all_files_for_workspace_into_file_manager,
        ops::{check_program, collect_errors, compile_program, optimize_program, report_errors},
        parse_all,
    },
    nargo_toml::{find_root, get_package_manifest, resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::fs::artifact::save_program_to_file,
    noirc_driver::{CompilationResult, CompileOptions, CrateName, NOIR_ARTIFACT_VERSION_STRING},
    provekit_common::{file::write, HashConfig},
    provekit_noir::{Prover, Verifier},
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    rayon::prelude::*,
    std::{
        path::{Path, PathBuf},
        str::FromStr,
    },
    tracing::instrument,
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
        let pkp_path = resolve_key_path(self.pkp_path.as_deref(), "pkp")?;
        let pkv_path = resolve_key_path(self.pkv_path.as_deref(), "pkv")?;
        write(&Prover::from_noir_proof_scheme(scheme.clone()), &pkp_path)
            .context("while writing prover key")?;
        write(&Verifier::from_noir_proof_scheme(scheme), &pkv_path)
            .context("while writing verifier key")?;
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
