pub mod constants;
pub mod types;
pub mod dlog;
pub mod commitment;
pub mod query;
pub mod nullifier;
pub mod merkle_proof;

use constants::{MAX_DEPTH, NUM_KEYS};
use nullifier::oprf_nullifier;
use types::{OprfNullifierInputs, OprfNullifierOutputs};

pub fn main(inputs: OprfNullifierInputs<MAX_DEPTH, NUM_KEYS>) -> pub OprfNullifierOutputs {
    oprf_nullifier(inputs)
}
