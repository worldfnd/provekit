// Sha256 example
//
// Calls Sha256 from the standard library.
//
// The Compiler sees this special function and creates an ACIR gate
//
// The ACIR SHA256 gate is passed to PLONK who should
// know how to create the necessary constraints.
//
// Not yet here: For R1CS, it is more about manipulating arithmetic gates to get performance
// This can be done in ACIR!
fn main(x: Field, result: [u8; 32], input: [u8; 2], toggle: bool) {
    let x = hash(x, 1234);

    // We use the `as` keyword here to denote the fact that we want to take just the first byte from the x Field
    // The padding is taken care of by the program
    // docs:start:sha256_var
    let digest = std::hash::sha256_var([x as u8], 1);
    // docs:end:sha256_var
    assert(digest == result);


    let digest = std::hash::sha256([x as u8]);
    assert(digest == result);

    // variable size
    let size: Field = 1 + toggle as Field;
    let var_sha = std::hash::sha256_var(input, size as u64);
    assert(var_sha == std::hash::sha256_var(input, 1));
}

fn sq(x: Field) -> Field {
    x * x
}

fn cu(x: Field) -> Field {
    x * x * x
}

// hashes two inputs
fn hash(val: Field, salt: Field) -> Field {
    // let mut slt = salt as u64;
    // let val = val as u64;
    let salts = [
        0xf8bf3bd6c22ba3b1bf3ab2e3fb40818cd4217ffbaf294ca42331d4e3043a0a6,
        0x388c9fcf30fc2841d648f46bad01dd10bee9dc184d25eabc9f617021109cec3,
        0x2bb7f397c5941ac67befa8b232f15c8853dac263da793555441a90cec83b6454,
        0x17f389b52f9ea7a98874a4a31ef6a7beb43fb17db0e499250bb3f0181c59fb21,
        0x3a2090eacb897a31fb10561d560a9aeec24b7ad14d17b145f20c875a0b28c7c,
        0xc398534f0eb580f1fe4bf64553389e67cca4714399430e09619dcbee17ba099,
        0x7095ac9fda46afa7f181259e3635feffa7f11ee63f3ee777a5cebf4822328c4,
        0x2046f7cf1c8f13ef2b69cbc8bc0d5d809f82568abe2b33d1cd060958b1ced683,
    ];

    let v = val * salts[0];
    let v = v * v * v * (salt + salts[1]); // v ** 3
    let v = sq(sq(v)) * v * (salt + salts[2]); // v ** 5
    let v2 = sq(v);
    let v = cu(v2) * v * (salt + salts[3]); // v ** 7
    let v2 = sq(v);
    let v4 = sq(v2);
    let v = sq(v4) * v2 * v * (salt + salts[5]); // v ** 11
    let v4 = sq(sq(v));
    let v = cu(v4) * v * (salt + salts[6]); // v ** 13
    let v = sq(sq(sq(sq(v)))) * v * (salt + salts[7]); // v ** 17
    let v2 = sq(v);
    let v = sq(sq(sq(v2))) * v2 * v * (salt + salts[7]); // v ** 19

    v
}
