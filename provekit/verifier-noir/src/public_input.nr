// Public Input Binding (Poseidon2)
//
// Two checks from provekit/verifier/src/whir_r1cs.rs:
//
// 1. Hash binding: `public_inputs_hash == HashConfig::Poseidon2.hash_field_elements(inputs)`
//    which on the Rust side is `poseidon2::poseidon2_hash(inputs)` - the length-IV sponge
//    hash with `state[3] = n * 2^64`. Computed here via `poseidon2_sponge_hash` (shared
//    with Merkle leaf hashing).
//
// 2. Geometric evaluation:
//    public_eval == 1 + x*p0 + x^2*p1 + ... + x^n*p_{n-1}
//    where p_i are the public inputs and x is a Fiat-Shamir challenge.

use crate::merkle::poseidon2_sponge_hash;

/// Compute the public inputs hash using the Poseidon2 length-IV sponge.
///
/// Matches `HashConfig::Poseidon2.hash_field_elements(inputs)` on the Rust
/// side. Produces a distinct non-zero value for the empty-input case
/// (the capacity-lane IV is `0 * 2^64 = 0` but a final permute still runs).
pub fn hash_public_inputs<let N: u32>(
    inputs: [Field; N],
    n_inputs: u32,
) -> Field {
    poseidon2_sponge_hash(inputs, n_inputs)
}

/// Verify the public input hash binding.
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

/// Verify the geometric public evaluation binding.
///
/// The weight covers positions [0, 1, ..., N] where position 0 is the
/// R1CS constant 1 and positions 1..=N are the public inputs.
///
/// expected = 1 + x*p0 + x^2*p1 + ... + x^n*p_{n-1}
///
/// Matches `verify_public_input_binding` in whir_r1cs.rs.
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
