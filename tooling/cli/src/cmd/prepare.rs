use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::write, HashConfig, Verifier},
    provekit_prover::{write_pkp, Groth16CommitmentInfo, Groth16Prover, Prover},
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    std::{path::PathBuf, str::FromStr},
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

                write_pkp(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
                write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
            }
            Backend::Groth16 => {
                use {
                    ark_serialize::CanonicalSerialize,
                    provekit_common::noir_proof_scheme::NoirProofScheme,
                };

                // Extract R1CS and witness builders from the compiled scheme
                let NoirProofScheme::Noir(d) = scheme else {
                    anyhow::bail!("Groth16 backend is not supported with the Mavros compiler");
                };

                let abi = d.witness_generator.abi.clone();
                let mut r1cs = d.r1cs;
                let program = d.program;
                let split_witness_builders = d.split_witness_builders;
                let witness_generator = d.witness_generator;
                let w1_size = d.whir_for_witness.w1_size;
                let challenge_offsets = d.whir_for_witness.challenge_offsets.clone();

                // The Noir compiler doesn't set num_public_inputs on the R1CS
                // (WHIR handles public inputs separately). For Groth16, we need
                // it to classify wires as public vs private. Compute from ABI.
                {
                    use noirc_abi::AbiVisibility;
                    let mut n_public: usize = abi
                        .parameters
                        .iter()
                        .filter(|p| p.is_public())
                        .map(|p| p.typ.field_count() as usize)
                        .sum();
                    if let Some(ret) = &abi.return_type {
                        if matches!(ret.visibility, AbiVisibility::Public) {
                            n_public += ret.abi_type.field_count() as usize;
                        }
                    }
                    r1cs.num_public_inputs = n_public;
                }
                let num_public = 1 + r1cs.num_public_inputs;

                // Build BSB22 commitment info: WHIR-style, one Pedersen commitment
                // over all private w1 wires, producing N challenges via hash_to_fr_multi.
                let num_challenges = challenge_offsets.len();
                let private_w1_wires: Vec<usize> = (num_public..w1_size).collect();
                let public_committed: Vec<usize> = (1..num_public).collect();

                let (commitment_info, groth16_ci, num_challenges_per_commitment) =
                    if num_challenges > 0 && !private_w1_wires.is_empty() {
                        // Sort challenge wire indices so they match the order
                        // in vk.g1_k (which is wire-index order from the setup loop).
                        let mut sorted_challenge_indices: Vec<usize> = challenge_offsets
                            .iter()
                            .map(|&offset| w1_size + offset)
                            .collect();
                        sorted_challenge_indices.sort_unstable();

                        let ci = Groth16CommitmentInfo {
                            public_committed:  public_committed.clone(),
                            private_committed: private_w1_wires.clone(),
                            challenge_indices: sorted_challenge_indices.clone(),
                        };
                        // For setup, use first sorted challenge wire as commitment_index
                        let g16_ci = vec![provekit_groth16::CommitmentInfo {
                            public_and_commitment_committed: public_committed,
                            private_committed:               private_w1_wires.clone(),
                            commitment_index:                sorted_challenge_indices[0],
                            nb_public_committed:             r1cs.num_public_inputs,
                        }];
                        let ncpc = vec![num_challenges];
                        (vec![ci], g16_ci, ncpc)
                    } else {
                        (vec![], vec![], vec![])
                    };

                info!(
                    num_challenges,
                    num_private_committed = private_w1_wires.len(),
                    num_public_inputs = r1cs.num_public_inputs,
                    w1_size,
                    "Running Groth16 trusted setup..."
                );
                // All challenge wire indices for setup (sorted to match vk.g1_k order)
                let mut challenge_wire_indices: Vec<usize> = challenge_offsets
                    .iter()
                    .map(|&offset| w1_size + offset)
                    .collect();
                challenge_wire_indices.sort_unstable();

                let (pk, vk) = provekit_groth16::setup::setup(
                    &r1cs,
                    &groth16_ci,
                    &num_challenges_per_commitment,
                    &challenge_wire_indices,
                )
                .context("while running Groth16 trusted setup")?;

                // The PK is held in typed form (`provekit_groth16::ProvingKey`)
                // and round-trips through arkworks bytes via the custom Serde
                // adapter when the .pkp is written. Only the VK still
                // serializes to bytes here, since `Verifier` keeps it as
                // `Vec<u8>` for cross-language interop.
                let mut vk_bytes = Vec::new();
                vk.serialize_uncompressed(&mut vk_bytes)
                    .context("while serializing Groth16 verifying key")?;

                info!(
                    vk_size = vk_bytes.len(),
                    vk_g1_k_len = vk.g1_k.len(),
                    vk_commitment_keys_len = vk.commitment_keys.len(),
                    vk_public_and_commitment_committed_len =
                        vk.public_and_commitment_committed.len(),
                    "Groth16 setup complete"
                );

                let prover = Prover::Groth16(Groth16Prover {
                    program,
                    r1cs: r1cs.clone(),
                    split_witness_builders,
                    witness_generator,
                    groth16_pk: pk,
                    commitment_info,
                });

                let verifier = Verifier {
                    hash_config,
                    r1cs,
                    whir_for_witness: None,
                    abi,
                    groth16_vk: Some(vk_bytes),
                };

                write_pkp(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
                write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;
            }
        }

        Ok(())
    }
}
