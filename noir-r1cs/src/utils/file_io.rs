use {
    acir::native_types::{WitnessStack, WitnessStackError},
    anyhow::{Context, Result},
    flate2::read::GzDecoder,
    serde::Deserialize,
    std::{
        fs::File,
        io::{BufReader, Read},
        path::Path,
    },
};

/// Deserialize WitnessStack from basic.gz
pub fn deserialize_witness_stack<F: for<'a> Deserialize<'a>>(
    file_path: impl AsRef<Path>,
) -> Result<WitnessStack<F>, WitnessStackError> {
    let file_path = file_path.as_ref();
    let file = File::open(file_path)
        .with_context(|| format!("while opening witness file `{}`", file_path.display()))
        .unwrap();

    let mut decoder = GzDecoder::new(BufReader::new(file));
    let mut decompressed_bytes = Vec::new();
    decoder
        .read_to_end(&mut decompressed_bytes)
        .expect("Failed to decompress");

    let witness_stack: WitnessStack<F> =
        bincode::deserialize(&decompressed_bytes).expect("Failed to deserialize");
    Ok(witness_stack)
}
