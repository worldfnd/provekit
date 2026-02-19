use sha256::sha256_var;

fn main() -> pub [u8; 32] {
    let bytes: [u8; 2048] = [0; 2048];
    let digest = sha256_var(bytes, 2048);
    digest
}
