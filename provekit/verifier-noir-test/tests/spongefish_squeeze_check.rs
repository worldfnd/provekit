//! Cross-impl proof: spongefish's `verifier_message::<Fr>()` squeezes 64 bytes
//! (a `DecodingFieldBuffer<Fr>`, sized `base_field_modulus_bytes + 32 = 64`),
//! then reduces mod p via `Fr::from_le_bytes_mod_order`. This is equivalent
//! to `lane0 + lane1 * R_2_POW_256_MOD_P`, where `lane0, lane1` are two
//! canonical-encoded lane field elements and `R_2_POW_256_MOD_P = 2^256 mod p`.
//!
//! Pinned constants and identities consumed by `verifier-noir/src/transcript.nr`.
//! Regression: prior lane-grain `squeeze_field` (32-byte squeeze) desynced the
//! Noir transcript from the Rust verifier on the FIRST OOD challenge squeeze
//! (see `transcript.nr::squeeze_field` docs).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use provekit_common::poseidon2::Poseidon2Sponge;
use spongefish::{Decoding, DuplexSpongeInterface};

#[test]
fn fr_decoding_squeezes_64_bytes_not_32() {
    let mut buf_size = <Fr as Decoding<[u8]>>::Repr::default();
    let actual_len = buf_size.as_mut().len();
    println!("Fr Decoding::Repr buffer size: {} bytes", actual_len);
    assert_eq!(actual_len, 64, "expected 64 bytes for Fr challenge");
}

#[test]
fn compute_2_pow_256_mod_p() {
    // 2^256 mod p, the constant needed to combine two lanes into a 64-byte
    // squeezed challenge.
    let mut bytes = [0u8; 64];
    bytes[32] = 1; // byte sequence representing 2^256
    let r = Fr::from_le_bytes_mod_order(&bytes);
    println!("2^256 mod p = {}", r.into_bigint());
}

#[test]
fn verify_two_lane_combine_matches_spongefish() {
    // Verify that Fr::from_le_bytes_mod_order(lane0_le ++ lane1_le)
    // equals (lane0 + lane1 * 2^256) mod p, where each lane Fr is
    // already a canonical field element.
    let mut s = Poseidon2Sponge::default();
    s.absorb(&[42u8; 64]);

    // Squeeze 64 raw bytes
    let mut buf = [0u8; 64];
    s.squeeze(&mut buf);
    let direct = Fr::from_le_bytes_mod_order(&buf);

    // The same 64 bytes interpreted as two 32-byte lane chunks
    let lane0 = Fr::from_le_bytes_mod_order(&buf[0..32]);
    let lane1 = Fr::from_le_bytes_mod_order(&buf[32..64]);

    // 2^256 mod p
    let mut r_bytes = [0u8; 64];
    r_bytes[32] = 1;
    let r = Fr::from_le_bytes_mod_order(&r_bytes);

    let combined = lane0 + lane1 * r;
    println!("direct   = {}", direct.into_bigint());
    println!("combined = {}", combined.into_bigint());
    assert_eq!(direct, combined, "two-lane combine formula valid");
}

#[test]
fn lane_vs_spongefish_squeeze_diverge() {
    // Reproduce typical DS state: absorb 128 bytes (protocol+session+instance).
    let mut s = Poseidon2Sponge::default();
    s.absorb(&[1u8; 64]);
    s.absorb(&[2u8; 32]);
    s.absorb(&[3u8; 32]);

    // Squeeze the way spongefish does for Fr: 64 bytes.
    let mut buf64 = [0u8; 64];
    s.squeeze(&mut buf64);
    let fr_spongefish = Fr::from_le_bytes_mod_order(&buf64);
    println!("Spongefish-style Fr (64 bytes): {}", fr_spongefish.into_bigint());

    // Compare to lane-style: squeeze 32 bytes only.
    let mut s2 = Poseidon2Sponge::default();
    s2.absorb(&[1u8; 64]);
    s2.absorb(&[2u8; 32]);
    s2.absorb(&[3u8; 32]);
    let mut buf32 = [0u8; 32];
    s2.squeeze(&mut buf32);
    let fr_lane = Fr::from_le_bytes_mod_order(&buf32);
    println!("Lane-style Fr (32 bytes): {}", fr_lane.into_bigint());

    assert_ne!(fr_spongefish, fr_lane, "diverge as expected");
}
