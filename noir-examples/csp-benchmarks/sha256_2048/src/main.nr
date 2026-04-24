use sha256::sha256_var;

global INPUT_SIZE: u32 = 2048;

fn main(input: [u8; INPUT_SIZE], input_len: u32) -> pub [u8; 32] {
    sha256_var(input, input_len)
}
