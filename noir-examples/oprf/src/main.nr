pub(crate) mod constants;
pub(crate) mod types;
pub(crate) mod dlog;
pub(crate) mod commitment;
pub(crate) mod query;
pub(crate) mod nullifier;
pub(crate) mod merkle_proof;

use constants::{MAX_DEPTH, NUM_KEYS};
use nullifier::oprf_nullifier;
use types::{OprfNullifierInputs, OprfNullifierOutputs, PublicKey};

pub fn main(
    cred_pk: pub PublicKey,
    current_time_stamp: pub u64,
    root: pub Field,
    depth: pub Field,
    rp_id: pub Field,
    action: pub Field,
    oprf_pk: pub PublicKey,
    nonce: pub Field,
    signal_hash: pub Field,
    inputs: OprfNullifierInputs<MAX_DEPTH, NUM_KEYS>,
) -> pub OprfNullifierOutputs {
    oprf_nullifier(
        cred_pk,
        current_time_stamp,
        root,
        depth,
        rp_id,
        action,
        oprf_pk,
        nonce,
        signal_hash,
        inputs,
    )
}
