fn main(a: [u8; 90]) -> pub [u8; 32] {
    let mut x = 3;
    if a[0] == 1 {
        // This is not true, but it doesn't matter
        x = 5;
    }
    let result = noir_native_sha256::ryan_sha256_noir::sha256_var(a, x + (a.len() as u64) - x);

    println("The result is:");
    println(result);

    result
}
