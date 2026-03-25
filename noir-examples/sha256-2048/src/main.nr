use sha256::sha256_var;

/// SHA-256 hash of 2048 bytes (33 compression calls).
fn main(input: [u8; 2048], expected: pub [u8; 32]) {
    let result = sha256_var(input, 2048);
    assert(result == expected);
}
