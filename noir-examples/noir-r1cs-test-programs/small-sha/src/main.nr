fn main(a: [u8; 3]) -> pub [u8; 32] {
    noir_native_sha256::ryan_sha256_noir::sha256_var(a, 3)
}
