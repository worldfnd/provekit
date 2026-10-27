use {
    crate::{noir_to_r1cs, witness_generator::NoirWitnessGeneratorBuilder},
    anyhow::{ensure, Context as _, Result},
    mavros_artifacts::{Artifact, ArtifactError, ArtifactParts, R1CS as MavrosR1CS},
    noirc_artifacts::program::ProgramArtifact,
    provekit_backend_bn254::{
        witness::WitnessBuilder, Bn254Field, MavrosColumnMap, MavrosSchemeData, NoirProofScheme,
        NoirSchemeData, NoirWitnessGenerator, PrintAbi,
    },
    provekit_common::WhirR1CSScheme,
    std::{collections::HashSet, fs::File, path::Path},
    tracing::{info, instrument},
};

fn convert_mavros_r1cs_to_provekit(
    mavros_r1cs: &MavrosR1CS,
    column_map: &MavrosColumnMap,
) -> provekit_common::R1CS<provekit_backend_bn254::FieldElement> {
    let num_witnesses = mavros_r1cs.witness_layout.size();
    let num_constraints = mavros_r1cs.constraints.len();

    let total_entries: usize = mavros_r1cs
        .constraints
        .iter()
        .map(|c| c.a.len() + c.b.len() + c.c.len())
        .sum();

    let mut r1cs = provekit_common::R1CS::<provekit_backend_bn254::FieldElement>::new();
    r1cs.add_witnesses(num_witnesses);
    r1cs.reserve_constraints(num_constraints, total_entries);

    let mut terms: Vec<(usize, provekit_backend_bn254::FieldElement)> = Vec::with_capacity(64);
    let mut a_buf: Vec<(u32, provekit_common::InternedFieldElement)> = Vec::with_capacity(64);
    let mut b_buf: Vec<(u32, provekit_common::InternedFieldElement)> = Vec::with_capacity(64);
    let mut c_buf: Vec<(u32, provekit_common::InternedFieldElement)> = Vec::with_capacity(64);

    for constraint in &mavros_r1cs.constraints {
        for (src, dst) in [
            (&constraint.a, &mut a_buf),
            (&constraint.b, &mut b_buf),
            (&constraint.c, &mut c_buf),
        ] {
            terms.clear();
            terms.extend(
                src.iter()
                    .map(|(idx, coeff)| (column_map.constraint_column(*idx), *coeff)),
            );
            canonicalize_row(&mut terms);
            dst.clear();
            dst.extend(
                terms
                    .iter()
                    .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
            );
        }

        r1cs.push_constraint(
            a_buf.iter().copied(),
            b_buf.iter().copied(),
            c_buf.iter().copied(),
        );
    }

    r1cs
}

/// Sparse rows need sorted, unique columns.
fn canonicalize_row(terms: &mut Vec<(usize, provekit_backend_bn254::FieldElement)>) {
    use ark_ff::Zero as _;
    terms.sort_by_key(|&(idx, _)| idx);
    let mut write = 0;
    for read in 0..terms.len() {
        if write > 0 && terms[write - 1].0 == terms[read].0 {
            let coeff = terms[read].1;
            terms[write - 1].1 += coeff;
        } else {
            terms[write] = terms[read];
            write += 1;
        }
    }
    terms.truncate(write);
    terms.retain(|(_, coeff)| !coeff.is_zero());
}

pub struct NoirCompiler;

impl NoirCompiler {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    pub fn from_file(
        path: impl AsRef<Path> + std::fmt::Debug,
        hash_config: provekit_common::HashConfig,
        witness_mode: provekit_common::WitnessCommitmentMode,
    ) -> Result<NoirProofScheme> {
        let file = File::open(path).context("while opening Noir program")?;
        let program = serde_json::from_reader(file).context("while reading Noir program")?;

        Self::from_program(program, hash_config, witness_mode)
    }

    #[instrument(skip_all)]
    pub fn from_program(
        program: ProgramArtifact,
        hash_config: provekit_common::HashConfig,
        witness_mode: provekit_common::WitnessCommitmentMode,
    ) -> Result<NoirProofScheme> {
        provekit_backend_bn254::register();

        info!("Program noir version: {}", program.noir_version);
        info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        let main = &program.bytecode.functions[0];
        info!("ACIR: {} opcodes.", main.opcodes.len());

        let (mut r1cs, mut witness_map, mut witness_builders) = noir_to_r1cs(main)?;
        info!(
            "R1CS {} constraints, {} witnesses, A {} entries, B {} entries, C {} entries",
            r1cs.num_constraints(),
            r1cs.num_witnesses(),
            r1cs.a.num_entries(),
            r1cs.b.num_entries(),
            r1cs.c.num_entries()
        );

        let acir_public_inputs_indices_set: HashSet<u32> =
            main.public_inputs().indices().iter().cloned().collect();
        r1cs.num_public_inputs = acir_public_inputs_indices_set.len();

        // Gaussian elimination optimization pass
        let opt_stats = crate::optimize_r1cs(
            &mut r1cs,
            &mut witness_builders,
            &mut witness_map,
            &acir_public_inputs_indices_set,
        )?;
        info!(
            "After GE optimization: {} constraints, {} witnesses ({} eliminated, {:.1}% \
             constraint reduction)",
            opt_stats.constraints_after,
            opt_stats.witnesses_after,
            opt_stats.eliminated,
            opt_stats.constraint_reduction_percent()
        );

        let has_public_inputs = !acir_public_inputs_indices_set.is_empty();
        let (split_witness_builders, remapped_r1cs, remapped_witness_map, challenge_offsets) =
            WitnessBuilder::split_and_prepare_layers(
                &witness_builders,
                r1cs,
                witness_map,
                acir_public_inputs_indices_set,
            )?;
        let num_challenges = challenge_offsets.len();
        let num_real = remapped_r1cs.num_witnesses();
        let num_virtual = remapped_r1cs.num_virtual;
        info!(
            "Witness split: w1 = {}, w2 = {} (real, committed) + {} virtual (solving only)",
            split_witness_builders.w1_size,
            num_real - split_witness_builders.w1_size,
            num_virtual
        );

        let witness_generator =
            NoirWitnessGenerator::new(&program, remapped_witness_map, num_real + num_virtual);

        let whir_for_witness = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(
            &remapped_r1cs,
            split_witness_builders.w1_size,
            num_challenges,
            challenge_offsets,
            has_public_inputs,
            hash_config,
            witness_mode,
        )?;

        Ok(NoirProofScheme::Noir(NoirSchemeData {
            program: program.bytecode,
            r1cs: remapped_r1cs,
            split_witness_builders,
            witness_generator,
            whir_for_witness,
            hash_config,
        }))
    }
}

pub struct MavrosCompiler;

impl MavrosCompiler {
    #[instrument(skip_all)]
    pub fn compile(
        artifact_path: impl AsRef<Path> + std::fmt::Debug,
        hash_config: provekit_common::HashConfig,
        witness_mode: provekit_common::WitnessCommitmentMode,
    ) -> Result<NoirProofScheme> {
        provekit_backend_bn254::register();
        info!("Reading Mavros artifact from {:?}", artifact_path);
        let bytes =
            std::fs::read(artifact_path.as_ref()).context("while reading the Mavros artifact")?;
        let artifact = Artifact::<provekit_backend_bn254::FieldElement>::from_bytes(&bytes)
            .map_err(|err| match err {
                ArtifactError::MissingHeader | ArtifactError::UnsupportedVersion { .. } => {
                    anyhow::anyhow!(
                        "{err}; recompile the circuit with the Mavros revision pinned in the \
                         workspace `Cargo.toml`"
                    )
                }
                other => anyhow::Error::new(other),
            })
            .with_context(|| format!("while reading the Mavros artifact {artifact_path:?}"))?;
        let abi: noirc_abi::Abi = serde_json::from_slice(artifact.abi())
            .context("while decoding the ABI in the Mavros artifact")?;
        let mavros_digest = artifact.circuit_digest();
        let ArtifactParts {
            compiler,
            manifest,
            r1cs: mavros_r1cs,
            bytecode: binary,
            ..
        } = artifact.into_parts();

        info!(
            "Mavros {compiler} R1CS: {} constraints, witness layout: algebraic={}, challenges={}, \
             circuit digest={}",
            mavros_r1cs.constraints.len(),
            mavros_r1cs.witness_layout.algebraic_size,
            mavros_r1cs.witness_layout.challenges_size,
            mavros_artifacts::hex(&mavros_digest),
        );

        let column_map =
            MavrosColumnMap::from_manifest(&manifest, &abi, mavros_r1cs.witness_layout.size())
                .context("while mapping Mavros columns onto ProveKit public inputs")?;
        let num_public_inputs = column_map.num_public_inputs();

        let challenges_size = mavros_r1cs.witness_layout.challenges_size;
        let challenge_offsets: Vec<usize> = (0..challenges_size).collect();
        let mut r1cs = convert_mavros_r1cs_to_provekit(&mavros_r1cs, &column_map);
        r1cs.num_public_inputs = num_public_inputs;

        let whir_for_witness = WhirR1CSScheme::<Bn254Field>::new_for_r1cs(
            &r1cs,
            mavros_r1cs.witness_layout.pre_commitment_size(),
            challenges_size,
            challenge_offsets,
            num_public_inputs > 0,
            hash_config,
            witness_mode,
        )?;

        Ok(NoirProofScheme::Mavros(MavrosSchemeData {
            abi,
            num_public_inputs,
            whir_for_witness,
            binary,
            r1cs,
            constraints_layout: mavros_r1cs.constraints_layout,
            witness_layout: mavros_r1cs.witness_layout,
            hash_config,
            column_map,
            mavros_digest,
        }))
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::NoirCompiler,
        ark_std::One,
        provekit_backend_bn254::{
            witness::{ConstantTerm, DigitalDecompositionWitnesses, SumTerm, WitnessBuilder},
            FieldElement, NoirProofScheme,
        },
        serde::{Deserialize, Serialize},
        std::path::PathBuf,
    };

    #[track_caller]
    fn test_serde<T>(value: &T)
    where
        T: std::fmt::Debug + PartialEq + Serialize + for<'a> Deserialize<'a>,
    {
        let json = serde_json::to_string(value).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(value, &deserialized);

        let bin = postcard::to_allocvec(value).unwrap();
        let deserialized = postcard::from_bytes(&bin).unwrap();
        assert_eq!(value, &deserialized);
    }

    #[test]
    fn test_noir_proof_scheme_serde() {
        let path = PathBuf::from("../../tooling/provekit-bench/benches/poseidon_rounds.json");
        let proof_scheme = NoirCompiler::from_file(
            path,
            provekit_common::HashConfig::default(),
            provekit_common::WitnessCommitmentMode::default(),
        )
        .unwrap();

        if let NoirProofScheme::Noir(d) = &proof_scheme {
            test_serde(&d.r1cs);
            test_serde(&d.split_witness_builders);
            test_serde(&d.witness_generator);
            test_serde(&d.whir_for_witness);
        } else {
            panic!("Expected Noir variant");
        }
    }

    #[test]
    fn test_witness_builder_serde() {
        let sum_term = SumTerm(Some(FieldElement::one()), 2);
        test_serde(&sum_term);
        let constant_term = ConstantTerm(2, FieldElement::one());
        test_serde(&constant_term);
        let witness_builder = WitnessBuilder::Constant(constant_term);
        test_serde(&witness_builder);

        let digital_decomposition = DigitalDecompositionWitnesses {
            log_bases:                  vec![1, 2],
            num_witnesses_to_decompose: 2,
            witnesses_to_decompose:     vec![3, 4],
            output_indices:             vec![5, 6, 7, 8],
        };
        test_serde(&digital_decomposition);
        test_serde(&WitnessBuilder::DigitalDecomposition(
            digital_decomposition.clone(),
        ));
        test_serde(&WitnessBuilder::ChunkDecompose {
            output_indices: vec![9, 10],
            packed:         11,
            chunk_bits:     vec![8, 8],
        });
        test_serde(&WitnessBuilder::SpreadBitExtract {
            output_indices: vec![12, 13],
            chunk_bits:     vec![4, 4],
            sum_terms:      vec![sum_term],
            extract_even:   true,
        });
    }
}
