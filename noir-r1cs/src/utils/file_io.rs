use {
    crate::types::Program,
    acir::native_types::{WitnessStack, WitnessStackError},
    anyhow::{Context, Result},
    base64::{self, Engine},
    flate2::read::GzDecoder,
    serde::Deserialize,
    serde_json,
    std::{
        fs::{self, File},
        io::{BufReader, Read},
    },
};

pub fn program_at_path(acir_path: String) -> Program {
    let json_string =
        fs::read_to_string(acir_path).expect("There was a problem reading the file content");
    let json_str: &str = &json_string;
    let json: serde_json::Value =
        serde_json::from_str(json_str).expect("There was a problem parsing the json program");
    let Some(bytecode_str) = json["bytecode"].as_str() else {
        panic!("Expected a different circuit format")
    };
    let bytecode: &[u8] = &base64::prelude::BASE64_STANDARD
        .decode(bytecode_str)
        .expect("There was a problem decoding the program from base 64");
    let program = Program::deserialize_program(bytecode);
    program.unwrap()
}

/// Deserialize WitnessStack from basic.gz
pub fn deserialize_witness_stack<F: for<'a> Deserialize<'a>>(
    file_path: &str,
) -> Result<WitnessStack<F>, WitnessStackError> {
    let file = File::open(file_path)
        .context("while opening witness file")
        .unwrap();
    let mut decoder = GzDecoder::new(BufReader::new(file));

    let mut decompressed_bytes = Vec::new();
    decoder.read_to_end(&mut decompressed_bytes).unwrap();

    let witness_stack: WitnessStack<F> = bincode::deserialize(&decompressed_bytes).unwrap();
    Ok(witness_stack)
}
