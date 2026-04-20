use sha256::sha256_var;

// Chain 17 SHA-256 rounds over a 32-byte state.
global NUM_SHA_CALLS: u32 = 17;

fn main(input: [u8; 32], expected: pub [u8; 32]) {
    let mut data = input;
    for _ in 0..NUM_SHA_CALLS {
        data = sha256_var(data, 32);
    }
    assert(data == expected);
}
