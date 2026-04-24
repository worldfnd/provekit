use noir_native_sha256::ryan_sha256_noir;

global INPUT_SIZE: u32 = 128;

fn main(input: [u8; INPUT_SIZE], input_len: u64) -> pub [u8; 32] {
    ryan_sha256_noir::sha256_var(input, input_len)
}
