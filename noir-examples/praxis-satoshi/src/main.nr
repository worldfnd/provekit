// Real Noir circuit for Praxis 100-bit Witness Encryption demo.
// Checks that the private 56-bit name (7 ASCII bytes, little-endian bit order)
// equals the hardcoded string "satoshi".
//
// Each bit is a Noir `bool`, so ProveKit's R1CS compiler emits pure algebraic
// Boolean constraints with zero LogUp challenges, mapping directly to Praxis's
// Boolean Quadratic System (BQS) with N = 56 Boolean unknowns.
fn main(name_bits: [bool; 56]) {
    // ASCII bytes of "satoshi": [115, 97, 116, 111, 115, 104, 105]
    let expected_bytes: [Field; 7] = [115, 97, 116, 111, 115, 104, 105];

    // Pack expected bytes into a single Field element (base-256 little-endian).
    let mut expected_packed: Field = 0;
    let mut byte_base: Field = 1;
    for b in 0..7 {
        expected_packed += expected_bytes[b] * byte_base;
        byte_base *= 256;
    }

    // Reconstruct the 7 bytes from the 56 input bits and check each byte.
    let mut packed: Field = 0;
    let mut bit_weight: Field = 1;
    for b in 0..7 {
        let mut byte_val: Field = 0;
        let mut inner_weight: Field = 1;
        for k in 0..8 {
            let bit = name_bits[b * 8 + k] as Field;
            byte_val += bit * inner_weight;
            packed += bit * bit_weight;
            inner_weight *= 2;
            bit_weight *= 2;
        }
        assert(byte_val == expected_bytes[b]);
    }

    // Quadratic binding check so the compiled R1CS has a genuine non-linear constraint.
    assert(packed * packed == expected_packed * expected_packed);
    assert(packed == expected_packed);
}
