use {
    crate::{
        noir_to_r1cs, whir_r1cs::WhirR1CSSchemeBuilder,
        witness_generator::NoirWitnessGeneratorBuilder,
    },
    anyhow::{ensure, Context as _, Result},
    mavros_artifacts::R1CS as MavrosR1CS,
    noirc_abi::AbiVisibility,
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{
        utils::{convert_mavros_r1cs_to_provekit, PrintAbi},
        witness::{NoirWitnessGenerator, WitnessBuilder},
        MavrosSchemeData, NoirProofScheme, NoirSchemeData, WhirR1CSScheme,
    },
    serde::Deserialize,
    std::{collections::HashSet, fs::File, path::Path},
    tracing::{info, instrument},
};

pub struct NoirCompiler;

impl NoirCompiler {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    pub fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<NoirProofScheme> {
        let file = File::open(path).context("while opening Noir program")?;
        let program = serde_json::from_reader(file).context("while reading Noir program")?;

        Self::from_program(program, hash_config)
    }

    #[instrument(skip_all)]
    pub fn from_program(program: ProgramArtifact) -> Result<NoirProofScheme> {
        info!("Program noir version: {}", program.noir_version);
        info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        let (r1cs, witness_map, witness_builders) = noir_to_r1cs(main)?;
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

        let has_public_inputs = !acir_public_inputs_indices_set.is_empty();
        let (split_witness_builders, remapped_r1cs, remapped_witness_map, num_challenges) =
            WitnessBuilder::split_and_prepare_layers(
                &witness_builders,
                r1cs,
                witness_map,
                acir_public_inputs_indices_set,
            )?;
        info!(
            "Witness split: w1 size = {}, w2 size = {}",
            split_witness_builders.w1_size,
            remapped_r1cs.num_witnesses() - split_witness_builders.w1_size
        );

        let witness_generator = NoirWitnessGenerator::new(
            &program,
            remapped_witness_map,
            remapped_r1cs.num_witnesses(),
        );

        let whir_for_witness = WhirR1CSScheme::new_for_r1cs(
            &remapped_r1cs,
            split_witness_builders.w1_size,
            num_challenges,
            has_public_inputs,
            hash_config.engine_id(),
        );

        Ok(NoirProofScheme::Noir(NoirSchemeData {
            program: program.bytecode,
            r1cs: remapped_r1cs,
            split_witness_builders,
            witness_generator,
            whir_for_witness,
        }))
    }
}

#[derive(Deserialize)]
struct BasicArtifacts {
    abi:           noirc_abi::Abi,
    ad_binary:     Vec<u64>,
    witgen_binary: Vec<u64>,
}

pub struct MavrosCompiler;

impl MavrosCompiler {
    #[instrument(skip_all)]
    pub fn compile(
        basic_path: impl AsRef<Path> + std::fmt::Debug,
        r1cs_path: impl AsRef<Path> + std::fmt::Debug,
    ) -> Result<NoirProofScheme> {
        info!("Reading basic artifacts from {:?}", basic_path);
        let basic_file = File::open(&basic_path).context("while opening basic artifacts")?;
        let basic: BasicArtifacts =
            serde_json::from_reader(basic_file).context("while reading basic artifacts")?;
        let abi = basic.abi;

        info!("Reading R1CS from {:?}", r1cs_path);
        let r1cs_bytes = std::fs::read(r1cs_path.as_ref()).context("while reading R1CS file")?;
        let mavros_r1cs: MavrosR1CS =
            bincode::deserialize(&r1cs_bytes).context("while deserializing R1CS from bincode")?;

        info!(
            "R1CS: {} constraints, witness layout: algebraic={}, challenges={}",
            mavros_r1cs.constraints.len(),
            mavros_r1cs.witness_layout.algebraic_size,
            mavros_r1cs.witness_layout.challenges_size,
        );

        let mut num_public_inputs: usize = abi
            .parameters
            .iter()
            .filter(|p| p.is_public())
            .map(|p| p.typ.field_count() as usize)
            .sum();

        if let Some(ret) = &abi.return_type {
            if matches!(ret.visibility, AbiVisibility::Public) {
                num_public_inputs += ret.abi_type.field_count() as usize;
            }
        }

        let whir_for_witness = WhirR1CSScheme::new_from_mavros_r1cs(
            &mavros_r1cs,
            mavros_r1cs.witness_layout.pre_commitment_size(),
            mavros_r1cs.witness_layout.challenges_size,
            num_public_inputs > 0,
        );

        let r1cs = convert_mavros_r1cs_to_provekit(&mavros_r1cs);

        Ok(NoirProofScheme::Mavros(MavrosSchemeData {
            abi,
            num_public_inputs,
            whir_for_witness,
            witgen_binary: basic.witgen_binary,
            ad_binary: basic.ad_binary,
            r1cs,
            constraints_layout: mavros_r1cs.constraints_layout,
            witness_layout: mavros_r1cs.witness_layout,
        }))
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::NoirCompiler,
        ark_std::One,
        provekit_common::{
            witness::{ConstantTerm, SumTerm, WitnessBuilder},
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
        let proof_scheme = NoirCompiler::from_file(path).unwrap();

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
    }
}
