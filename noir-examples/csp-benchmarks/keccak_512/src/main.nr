use csp_keccak_lib::keccak256;

global INPUT_SIZE: u32 = 512;

fn main(msg: [u8; INPUT_SIZE], message_size: u32, result: [u8; 32]) {
    let digest = keccak256(msg, message_size);
    assert(digest == result);
}
