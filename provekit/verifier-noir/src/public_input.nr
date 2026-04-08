// Public Input Binding
//
// Two checks from provekit/verifier/src/whir_r1cs.rs:
//
// 1. Hash binding: public_inputs_hash == Skyscraper::compress chain
//    Uses skyscraper_noir::compress from PR #148.
//
// 2. Geometric evaluation:
//    public_eval == 1 + x*p0 + x^2*p1 + ... + x^n*p_{n-1}
//    where p_i are the public inputs and x is a Fiat-Shamir challenge.

use skyscraper_noir::compress;

// Compute the public inputs hash using Skyscraper compression chaining.
//
// Matches provekit/common/src/witness/mod.rs PublicInputs::hash():
//   0 inputs -> Field(0)
//   1 input  -> compress(p0, 0)
//   n inputs -> compress(compress(...compress(p0, p1), p2), ..., p_{n-1})
pub fn hash_public_inputs<let N: u32>(
    inputs: [Field; N],
    n_inputs: u32,
) -> Field {
    let mut result: Field = 0;
    if n_inputs == 1 {
        result = compress(inputs[0], 0);
    } else if n_inputs >= 2 {
        // Fold left: compress(p0, p1), then compress(result, p2), etc.
        let mut acc = compress(inputs[0], inputs[1]);
        for i in 2..N {
            if (i as u32) < n_inputs {
                acc = compress(acc, inputs[i]);
            }
        }
        result = acc;
    }
    result
}

// Verify the public input hash binding.
//
// Asserts that the prover's claimed hash matches the actual Skyscraper
// compression chain of the public inputs.
pub fn verify_public_input_hash<let N: u32>(
    claimed_hash: Field,
    inputs: [Field; N],
    n_inputs: u32,
) {
    let expected = hash_public_inputs(inputs, n_inputs);
    assert(
        claimed_hash == expected,
        "Public inputs hash mismatch",
    );
}

// Verify the geometric public evaluation binding.
//
// The weight covers positions [0, 1, ..., N] where position 0 is the
// R1CS constant 1 and positions 1..=N are the public inputs.
//
// expected = 1 + x*p0 + x^2*p1 + ... + x^n*p_{n-1}
//
// Matches verify_public_input_binding in whir_r1cs.rs.
pub fn verify_public_eval<let N: u32>(
    claimed_eval: Field,
    x: Field,
    inputs: [Field; N],
    n_inputs: u32,
) {
    let mut expected: Field = 1; // position 0: constant 1
    let mut x_pow = x;
    for i in 0..N {
        if (i as u32) < n_inputs {
            expected += x_pow * inputs[i];
            x_pow *= x;
        }
    }
    assert(
        claimed_eval == expected,
        "Public input binding check failed",
    );
}
