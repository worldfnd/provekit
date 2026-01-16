// Mimics the sha256 pattern - Brillig output NOT fully verified
unconstrained fn modify_array(arr: [u8; 8], len: u32) -> [u8; 8] {
    let mut result = arr;
    // This modification is NOT constrained
    if len > 4 {
        result[len - 1] = 99;
    }
    result
}

fn main(data: [u8; 8], len: pub u32) {
    // Use the Brillig output directly without constraining its contents
    let modified = unsafe { modify_array(data, len) };
    
    // Only check the first element - rest is unconstrained!
    assert(modified[0] == data[0]);
}
