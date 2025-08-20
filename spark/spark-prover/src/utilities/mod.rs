mod iopattern;

pub use iopattern::create_io_pattern;
use {
    anyhow::{Context, Result},
    noir_r1cs::R1CS,
    std::fs,
};

pub fn deserialize_r1cs(path_str: &str) -> Result<R1CS> {
    let json_str =
        fs::read_to_string(path_str).context("Error: Failed to open the r1cs.json file")?;
    serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")
}
