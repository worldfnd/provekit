use {
    acir::native_types::{WitnessStack, WitnessStackError},
    anyhow::{Context, Result},
    flate2::read::GzDecoder,
    serde::Deserialize,
    std::{
        fs::File,
        io::{BufReader, Read},
        path::PathBuf,
    },
};

/// Deserialize WitnessStack from basic.gz
pub fn deserialize_witness_stack<F: for<'a> Deserialize<'a>>(
    file_path: &PathBuf,
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
