use {
    acir::{circuit::Program, FieldElement},
    fm::FileId,
    noirc_abi::{Abi, AbiType},
    noirc_artifacts::program::ProgramArtifact,
    noirc_driver::DebugFile,
    noirc_errors::debug_info::ProgramDebugInfo,
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SerializableProgramArtifact {
    pub noir_version: String,
    pub hash:         u64,

    pub abi: BTreeMap<String, AbiType>,

    #[serde(
        serialize_with = "Program::serialize_program_base64",
        deserialize_with = "Program::deserialize_program_base64"
    )]
    pub bytecode: Program<FieldElement>,

    #[serde(
        serialize_with = "ProgramDebugInfo::serialize_compressed_base64_json",
        deserialize_with = "ProgramDebugInfo::deserialize_compressed_base64_json"
    )]
    pub debug_symbols: ProgramDebugInfo,

    /// Map of file Id to the source code so locations in debug info can be
    /// mapped to source code they point to.
    pub file_map: BTreeMap<FileId, DebugFile>,

    pub names:         Vec<String>,
    /// Names of the unconstrained functions in the program.
    pub brillig_names: Vec<String>,
}

impl From<ProgramArtifact> for SerializableProgramArtifact {
    fn from(value: ProgramArtifact) -> Self {
        let ProgramArtifact {
            noir_version,
            hash,
            abi,
            bytecode,
            debug_symbols,
            file_map,
            names,
            brillig_names,
        } = value;

        let abi = abi.to_btree_map();

        Self {
            noir_version,
            hash,
            abi,
            bytecode,
            debug_symbols,
            file_map,
            names,
            brillig_names,
        }
    }
}

impl From<SerializableProgramArtifact> for ProgramArtifact {
    fn from(value: SerializableProgramArtifact) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, noirc_artifacts::program::ProgramArtifact, std::fs::File};

    #[test]
    fn postcard_fuckery() -> anyhow::Result<()> {
        println!("{}", std::env::current_dir().unwrap().display());
        let file = File::open("../noir-examples/poseidon-rounds/target/basic.json")?;
        let program_artifact: ProgramArtifact = serde_json::from_reader(file)?;

        let nps_abi_encoded: Vec<u8> = postcard::to_stdvec(&nps.program.abi).unwrap();
        let nps_abi = postcard::from_bytes::<Abi>(&nps_abi_encoded);

        match nps_abi {
            Ok(_) => {}
            Err(err) => panic!("{}", err),
        }
    }
}
