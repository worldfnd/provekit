//! Public-input binding helpers for the recursive verifier.
//!
//! Provides:
//!   * `verify_public_input_hash` - asserts the prover-sent public-inputs
//!     hash matches the Poseidon2 length-IV hash of `[DST_FE, pi_0, pi_1, ...]`.
//!     Mirrors `provekit/common/src/hash_config.rs::hash_poseidon2`.
//!   * `verify_public_eval` - asserts the prover-sent public-eval value
//!     matches the geometric series `1 + sum_i x^(i+1) * pi_i`. Mirrors
//!     `provekit/verifier/src/whir_r1cs.rs::verify_public_input_binding`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/public_input_kat.rs`.

use crate::merkle::length_iv_hash;

/// Domain-separation tag = SHA256("PROVEKIT_PUBLIC_INPUTS_V1") reduced mod p.
///
/// Pinned here so the Noir verifier matches
/// `provekit/common/src/hash_config.rs::PUBLIC_INPUTS_DST_FE`. See
/// `provekit/verifier-noir-test/tests/public_input_kat.rs` for the cross-impl
/// guarantee.
global PUBLIC_INPUTS_DST_FE: Field = 17472337278469442596796739128721211927880374059638554206255737057576326046406;

/// Assert the prover's claimed public-inputs hash matches the Poseidon2
/// length-IV hash of `[DST_FE, pi_0, pi_1, ...]`.
pub fn verify_public_input_hash<let N: u32>(
    prover_msg: Field,
    public_inputs: [Field; N],
) {
    let tagged: [Field; N + 1] = build_tagged_inputs(public_inputs);
    let expected = length_iv_hash::<N + 1>(tagged);
    assert(prover_msg == expected);
}

fn build_tagged_inputs<let N: u32>(public_inputs: [Field; N]) -> [Field; N + 1] {
    let mut tagged: [Field; N + 1] = [0; N + 1];
    tagged[0] = PUBLIC_INPUTS_DST_FE;
    for i in 0..N {
        tagged[i + 1] = public_inputs[i];
    }
    tagged
}

/// Assert the prover's claimed `public_eval == 1 + sum_i x^(i+1) * pi_i`.
/// Matches the Rust reference's `verify_public_input_binding` exactly:
///
///   ```ignore
///   let mut expected = 1;
///   let mut x_pow = x;
///   for pi in public_inputs {
///       expected += x_pow * pi;
///       x_pow *= x;
///   }
///   assert(public_eval == expected);
///   ```
pub fn verify_public_eval<let N: u32>(
    prover_msg: Field,
    x: Field,
    public_inputs: [Field; N],
) {
    let mut expected: Field = 1;
    let mut x_pow: Field = x;
    for i in 0..N {
        expected += x_pow * public_inputs[i];
        x_pow *= x;
    }
    assert(prover_msg == expected);
}

// --- in-circuit KATs ---
//
// Two separate frozen KATs:
//   * EXPECTED_PI_HASH: hash of [DST_FE, 7, 11, 13] (3 public inputs).
//     Cross-impl guarantee lives in public_input_kat.rs.
//   * Pure geometric series: x=5, public_inputs=[7,11,13], expected=1936:
//     1 + 5*7 + 25*11 + 125*13 = 1 + 35 + 275 + 1625 = 1936. (No cross-impl
//     needed; the formula is a closed-form computation.)
//
// Value computed by HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13])
// (which prepends DST_FE and calls poseidon2_hash); frozen as a KAT.
// See provekit/verifier-noir-test/tests/public_input_kat.rs for the cross-impl
// guarantee.
global EXPECTED_PI_HASH: Field = 17671656644331470764259977637132622632100546348894486287549688249689905550951;

#[test]
fn verify_public_input_hash_matches_frozen_kat() {
    let public_inputs: [Field; 3] = [7, 11, 13];
    verify_public_input_hash::<3>(EXPECTED_PI_HASH, public_inputs);
}

#[test]
fn verify_public_eval_matches_canonical() {
    // expected = 1 + 5*7 + 25*11 + 125*13 = 1 + 35 + 275 + 1625 = 1936
    let public_inputs: [Field; 3] = [7, 11, 13];
    verify_public_eval::<3>(1936, 5, public_inputs);
}
