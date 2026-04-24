use csp_keccak_lib::keccak256;

global INPUT_SIZE: u32 = 1024;

fn main(msg: [u8; INPUT_SIZE], message_size: u64, result: [u8; 32]) {
    let digest = keccak256(msg, message_size as u32);
    assert(digest == result);
}
