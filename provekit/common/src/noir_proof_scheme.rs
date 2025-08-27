use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, WitnessBuilder},
        NoirElement, R1CS,
    },
    acir::circuit::Program,
    anyhow::Result,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noirc_abi::InputMap,
    serde::{Deserialize, Serialize},
    std::path::Path,
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:           Program<NoirElement>,
    pub r1cs:              R1CS,
    pub witness_builders:  Vec<WitnessBuilder>,
    pub witness_generator: NoirWitnessGenerator,
    pub whir_for_witness:  WhirR1CSScheme,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    pub fn read_witness(&self, prover_toml: impl AsRef<Path>) -> Result<InputMap> {
        let (input_map, _expected_return) =
            read_inputs_from_file(prover_toml.as_ref(), self.witness_generator.abi())?;

        Ok(input_map)
    }
}
