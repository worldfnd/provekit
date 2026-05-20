use {
    super::Command,
    acir::circuit::ExpressionWidth,
    anyhow::{anyhow, bail, Context as _, Result},
    argh::FromArgs,
    nargo::{
        insert_all_files_for_workspace_into_file_manager,
        ops::{check_program, collect_errors, compile_program, report_errors, transform_program},
        parse_all,
    },
    nargo_toml::{find_root, get_package_manifest, resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::fs::artifact::save_program_to_file,
    noirc_driver::{
        CompilationResult, CompileOptions, CrateName, DEFAULT_EXPRESSION_WIDTH,
        NOIR_ARTIFACT_VERSION_STRING,
    },
    provekit_common::{file::write, register_ntt, NoirProofScheme, Prover, Verifier},
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    rayon::prelude::*,
    std::path::{Path, PathBuf},
    tracing::instrument,
};

/// Compile a Noir program and build its prover and verifier keys.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct Args {
    /// directory containing Nargo.toml (default: current directory)
    #[argh(positional, default = "PathBuf::from(\".\")")]
    program_dir: PathBuf,

    /// name of the package to compile (default: enclosing package)
    #[argh(option)]
    package: Option<String>,

    /// compile every package in the workspace
    #[argh(switch)]
    workspace: bool,

    /// override the target directory for compiled artifacts
    #[argh(option)]
    target_dir: Option<PathBuf>,

    /// treat warnings as errors
    #[argh(switch)]
    deny_warnings: bool,

    /// suppress warnings
    #[argh(switch)]
    silence_warnings: bool,

    /// print the ACIR for the compiled circuit
    #[argh(switch)]
    print_acir: bool,

    /// skip the under-constrained-values check
    #[argh(switch)]
    skip_underconstrained_check: bool,

    /// skip the Brillig call-constraints check
    #[argh(switch)]
    skip_brillig_constraints_check: bool,

    /// force a full recompilation, ignoring cached artifacts
    #[argh(switch)]
    force: bool,

    /// output path for the prover key (default: `<circuit>.pkp`)
    #[argh(option, long = "pkp", short = 'p')]
    pkp_path: Option<PathBuf>,

    /// output path for the verifier key (default: `<circuit>.pkv`)
    #[argh(option, long = "pkv", short = 'v')]
    pkv_path: Option<PathBuf>,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        register_ntt();

        // Canonicalize so compiled artifacts embed absolute source paths,
        // matching `nargo compile` byte-for-byte in the `file_map` field.
        let program_dir = std::fs::canonicalize(&self.program_dir)
            .with_context(|| format!("canonicalizing {}", self.program_dir.display()))?;
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
                let program = transform_program(
                    program,
                    target_width(package.expression_width, options.expression_width),
                );
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
            let scheme = NoirProofScheme::from_program(artifact)
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
}

impl Args {
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

fn target_width(
    package: Option<ExpressionWidth>,
    options: Option<ExpressionWidth>,
) -> ExpressionWidth {
    options.or(package).unwrap_or(DEFAULT_EXPRESSION_WIDTH)
}
