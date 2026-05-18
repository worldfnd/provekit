//! Test-only library exposing fixed Poseidon2 KAT inputs / outputs so the
//! Cargo and Nargo sides can reference the same constants.

use {
    ark_bn254::Fr,
    ark_ff::PrimeField,
    provekit_common::poseidon2::Poseidon2Sponge,
    spongefish::DuplexSpongeInterface,
};

/// KAT input for cross-implementation Poseidon2 permutation testing.
pub fn kat_input() -> [Fr; 4] {
    [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]
}

/// Compute the expected output by running the Rust `poseidon2` crate.
pub fn kat_expected() -> [Fr; 4] {
    poseidon2::permutation::poseidon2_permutation(&kat_input())
}

/// Render a field element as a Noir-compatible decimal literal.
pub fn fr_to_noir_literal(fe: Fr) -> String {
    fe.into_bigint().to_string()
}

/// Run the canonical sponge KAT sequence through spongefish's
/// `Poseidon2Sponge` and return the four squeezed field elements.
///
/// Sequence: `default() -> absorb(field_to_bytes(1)) -> absorb(field_to_bytes(2)) ->
/// 4 x squeeze(32 bytes)`. Each 32-byte squeeze is interpreted as one
/// field element via `Fr::from_le_bytes_mod_order`.
pub fn sponge_kat_expected() -> [Fr; 4] {
    let mut s = Poseidon2Sponge::default();
    let one = fr_to_le_bytes(Fr::from(1u64));
    let two = fr_to_le_bytes(Fr::from(2u64));
    s.absorb(&one);
    s.absorb(&two);

    let mut outputs = [Fr::from(0u64); 4];
    for output in outputs.iter_mut() {
        let mut buf = [0u8; 32];
        s.squeeze(&mut buf);
        *output = Fr::from_le_bytes_mod_order(&buf);
    }
    outputs
}

fn fr_to_le_bytes(fe: Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bi = fe.into_bigint();
    for (i, limb) in bi.0.iter().enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    buf
}

/// Lane-grain duplex sponge replayed in Rust using the raw Poseidon2
/// permutation (no spongefish state-machine plumbing — we re-implement the
/// same state machine here so the test can set arbitrary initial state).
///
/// This must produce exactly the same outputs as Noir's `Transcript`. If they
/// disagree, either:
///   - the Rust replay below has a bug, OR
///   - the Noir `sponge.nr` state machine drifted from spongefish semantics.
fn lane_sponge_replay(
    mut state: [Fr; 4],
    mut absorb_pos: u32,
    mut squeeze_pos: u32,
    absorbs: &[Fr],
    squeeze_count: usize,
) -> Vec<Fr> {
    const RATE: u32 = 3;

    for &fe in absorbs {
        squeeze_pos = RATE;
        if absorb_pos == RATE {
            state = poseidon2::permutation::poseidon2_permutation(&state);
            absorb_pos = 0;
        }
        state[absorb_pos as usize] = fe;
        absorb_pos += 1;
    }

    let mut out = Vec::with_capacity(squeeze_count);
    for _ in 0..squeeze_count {
        if squeeze_pos == RATE {
            squeeze_pos = 0;
            state = poseidon2::permutation::poseidon2_permutation(&state);
        }
        out.push(state[squeeze_pos as usize]);
        squeeze_pos += 1;
    }

    out
}

/// Canonical Phase 1B transcript KAT sequence (same as Noir's
/// `transcript_init_absorb_squeeze_matches_frozen_kat`):
///
///   state = [10, 20, 30, 40], absorb_pos = 1, squeeze_pos = 3
///   absorb 7, absorb 8
///   squeeze, squeeze -> [a, b]
pub fn transcript_kat_expected() -> [Fr; 2] {
    let state = [
        Fr::from(10u64),
        Fr::from(20u64),
        Fr::from(30u64),
        Fr::from(40u64),
    ];
    let absorbs = [Fr::from(7u64), Fr::from(8u64)];
    let out = lane_sponge_replay(state, 1, 3, &absorbs, 2);
    [out[0], out[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Print the four field elements that Noir's
    /// `EXPECTED_PERMUTE_1234` global should hold. Run with `--nocapture`
    /// to capture them; paste into `verifier-noir/src/poseidon2.nr` in
    /// step 4 below.
    #[test]
    fn print_kat_expected_for_noir() {
        let expected = kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_PERMUTE_1234[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the four field elements that Noir's `EXPECTED_SPONGE_KAT`
    /// global should hold. Run with `--nocapture` to capture them.
    #[test]
    fn print_sponge_kat_expected_for_noir() {
        let expected = sponge_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_SPONGE_KAT[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }

    /// Print the two field elements that Noir's `EXPECTED_TRANSCRIPT_KAT`
    /// global should hold.
    #[test]
    fn print_transcript_kat_expected_for_noir() {
        let expected = transcript_kat_expected();
        for (i, fe) in expected.iter().enumerate() {
            println!("EXPECTED_TRANSCRIPT_KAT[{i}] = {}", fr_to_noir_literal(*fe));
        }
    }
}
