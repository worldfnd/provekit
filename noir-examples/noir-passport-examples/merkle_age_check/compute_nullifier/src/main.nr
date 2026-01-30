use common::calculate_private_nullifier;
use utils::types::{DG1Data, EContentData};

fn main(
    dg1: DG1Data,
    e_content: EContentData,
    sod_signature: [u8; 256],
) -> pub Field {
    calculate_private_nullifier(dg1, e_content, sod_signature)
}
