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
    provekit_common::{file::write, Groth16Prover, HashConfig, Prover, Verifier},
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    rayon::prelude::*,
    std::{
        path::{Path, PathBuf},
        str::FromStr,
    },
    tracing::{info, instrument},
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

#[derive(PartialEq, Eq, Debug)]
enum Backend {
    Whir,
    Groth16,
}

impl argh::FromArgValue for Backend {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "whir" => Ok(Backend::Whir),
            "groth16" => Ok(Backend::Groth16),
            other => Err(format!(
                "Unknown backend: {other}. Use \"whir\" or \"groth16\"."
            )),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Backend {
    Whir,
    Groth16,
}

impl argh::FromArgValue for Backend {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "whir" => Ok(Backend::Whir),
            "groth16" => Ok(Backend::Groth16),
            other => Err(format!(
                "Unknown backend: {other}. Use \"whir\" or \"groth16\"."
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

    /// proof backend to use: "whir" (default) or "groth16"
    #[argh(option, long = "backend", default = "Backend::Whir")]
    backend: Backend,

    /// output path for the prepared proof scheme
    #[argh(
        option,
        long = "pkp",
        short = 'p',
        default = "PathBuf::from(\"noir_proof_scheme.pkp\")"
    )]
    pkp_path: PathBuf,

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

        match self.backend {
            Backend::Whir => {
                let prover = Prover::from_noir_proof_scheme(scheme.clone());
                let verifier = Verifier::from_noir_proof_scheme(scheme);

                write(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
                write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
            }
            Backend::Groth16 => {
                use ark_serialize::CanonicalSerialize;
                use provekit_common::noir_proof_scheme::NoirProofScheme;

                // Extract R1CS and witness builders from the compiled scheme
                let NoirProofScheme::Noir(d) = scheme else {
                    anyhow::bail!("Groth16 backend is not supported with the Mavros compiler");
                };

                let abi = d.witness_generator.abi.clone();
                let r1cs = d.r1cs;
                let program = d.program;
                let split_witness_builders = d.split_witness_builders;
                let witness_generator = d.witness_generator;
                let w1_size = d.whir_for_witness.w1_size;
                let challenge_offsets = d.whir_for_witness.challenge_offsets.clone();
                let num_public = 1 + r1cs.num_public_inputs; // constant-1 + public inputs

                // Build BSB22 commitment info for circuits with challenges.
                //
                // ProveKit's challenges (LogUp, range checks, RAM/ROM) need a
                // commit-then-challenge flow. In WHIR this uses polynomial commitment
                // + Fiat-Shamir. For Groth16 we use Pedersen commitment + hashing:
                //   1. Commit all private w1 wires via Pedersen → C
                //   2. Hash(C || public_values) → challenge per wire
                //
                // One CommitmentInfo per challenge wire, all sharing the same
                // committed private wires but targeting different challenge wire indices.
                let commitment_info: Vec<provekit_common::Groth16CommitmentInfo> =
                    if !challenge_offsets.is_empty() && w1_size > num_public {
                        let private_committed: Vec<usize> = (num_public..w1_size).collect();
                        let public_committed: Vec<usize> = (1..num_public).collect();

                        challenge_offsets
                            .iter()
                            .map(|&offset| provekit_common::Groth16CommitmentInfo {
                                public_and_commitment_committed: public_committed.clone(),
                                private_committed: private_committed.clone(),
                                commitment_index: w1_size + offset,
                                nb_public_committed: public_committed.len(),
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                // Convert to groth16 CommitmentInfo for setup
                let groth16_ci: Vec<provekit_groth16::CommitmentInfo> = commitment_info
                    .iter()
                    .map(|ci| provekit_groth16::CommitmentInfo {
                        public_and_commitment_committed: ci.public_and_commitment_committed.clone(),
                        private_committed: ci.private_committed.clone(),
                        commitment_index: ci.commitment_index,
                        nb_public_committed: ci.nb_public_committed,
                    })
                    .collect();

                info!(
                    num_commitments = commitment_info.len(),
                    w1_size,
                    num_challenges = challenge_offsets.len(),
                    "Running Groth16 trusted setup..."
                );
                let (pk, vk) = provekit_groth16::setup::setup(&r1cs, &groth16_ci)
                    .context("while running Groth16 trusted setup")?;

                // Serialize proving key and verifying key
                let mut pk_bytes = Vec::new();
                pk.serialize_compressed(&mut pk_bytes)
                    .context("while serializing Groth16 proving key")?;

                let mut vk_bytes = Vec::new();
                vk.serialize_compressed(&mut vk_bytes)
                    .context("while serializing Groth16 verifying key")?;

                info!(
                    pk_size = pk_bytes.len(),
                    vk_size = vk_bytes.len(),
                    "Groth16 setup complete"
                );

                let prover = Prover::Groth16(Groth16Prover {
                    program,
                    r1cs: r1cs.clone(),
                    split_witness_builders,
                    witness_generator,
                    groth16_pk: pk_bytes,
                    commitment_info,
                });

                let verifier = Verifier {
                    hash_config,
                    r1cs,
                    whir_for_witness: None,
                    abi,
                    groth16_vk: Some(vk_bytes),
                };

                write(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
                write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
            }
        }

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
