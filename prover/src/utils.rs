#[allow(missing_docs)]
use whir::crypto::fields::Field256;
use ark_std::str::FromStr;

/// Convert vector string to vector field
pub fn stringvec_to_fieldvec(witness: &Vec<String>) -> Vec<Field256> {
    witness.iter().map(|x|{Field256::from_str(x).expect("Failed to create Field256 value from a string")}).collect()
}