//! # Poseidon2 implementation
//!
//! # References
//!
//! * Lorenzo Grassi, Dmitry Khovratovich, Markus Schofnegger (2023). Poseidon2:
//!   A Faster Version of the Poseidon Hash Function. <https://eprint.iacr.org/2023/323>
//! * Tomer Ashur, Thomas Buschman, Mohammad Mahzoun (2023).
//!   Algebraic Cryptanalysis of HADES Design Strategy: Application to POSEIDON and Poseidon2.
//!   <https://eprint.iacr.org/2023/537>
//! * Elena Andreeva, Rishiraj Bhattacharyya, Arnab Roy, Stefano Trevisani (2024).
//!   On Efficient and Secure Compression Modes for Arithmetization-Oriented Hashing.
//!   <https://eprint.iacr.org/2024/047>
//!
//! See also:
//! * https://github.com/HorizenLabs/poseidon2/blob/bb476b9ca38198cf5092487283c8b8c5d4317c4e/plain_implementations/src/poseidon2/poseidon2.rs
//! * https://github.com/Plonky3/Plonky3/blob/eeb4e37b20127c4daa871b2bad0df30a7c7380db/poseidon2/src/lib.rs

// https://hackmd.io/@hackmdhl/B1DdpVmK2
// https://extgit.iaik.tugraz.at/krypto/zkfriendlyhashzoo/-/blob/master/plain_impls/src/poseidon2/poseidon2_instance_bn256.rs?ref_type=heads
// https://eprint.iacr.org/2024/310.pdf

mod constants;

use {
    self::constants::{RC16, RC3},
    ark_bn254::Fr,
    ark_ff::Field,
    std::sync::atomic::{AtomicU32, Ordering},
};

pub static COUNT_3: AtomicU32 = AtomicU32::new(0);
pub static COUNT_16: AtomicU32 = AtomicU32::new(0);

/// Compress arbitrary length inputs.
// Compute 16-arry Merkle tree over input.
// Layers are zero padded.
// Compresses nodes using truncated width-16 Poseidon2.
// TODO: We can go to 24-ary tree with 24 width Poseidon2.
pub fn compress(input: &[Fr]) -> Fr {
    if input.len() <= 16 {
        let mut state = [Fr::ZERO; 16];
        state[..input.len()].copy_from_slice(input);
        permute_16(&mut state);
        state[0]
    } else {
        // Allocation free depth-first recursive computation
        let mut state = [Fr::ZERO; 16];
        // Compute the largest power of 16 < input.len();
        let chunk = 1 << (4 * ((input.len() - 1).ilog2() / 4));
        for (s, chunk) in state.iter_mut().zip(input.chunks(chunk)) {
            *s = compress(chunk);
        }
        permute_16(&mut state);
        state[0]
    }
}

pub fn permute_3(state: &mut [Fr; 3]) {
    COUNT_3.fetch_add(1, Ordering::Relaxed);
    mat_full_3(state);
    for rc in RC3.0 {
        state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
        state
            .iter_mut()
            .for_each(|x| *x *= x.square().square_in_place());
        mat_full_3(state);
    }
    for rc in RC3.1 {
        state[0] += rc;
        state[0] *= state[0].square().square_in_place();

        // TODO: Why is this one more operations than the MDS matrix?
        let sum: Fr = state.iter().sum();
        state[2].double_in_place();
        state.iter_mut().for_each(|s| *s += sum);
    }
    for rc in RC3.2 {
        state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
        state
            .iter_mut()
            .for_each(|x| *x *= x.square().square_in_place());
        mat_full_3(state);
    }
}

// OPT: Time spend: 53% in `mat_partial_16`, 31% in x^5, 11% in `mat_full_16`.
pub fn permute_16(state: &mut [Fr; 16]) {
    COUNT_16.fetch_add(1, Ordering::Relaxed);
    mat_full_16(state);
    for rc in RC16.0 {
        // TODO: Combine passes?
        // Should be able to fold the linear layer into the Montgomery reduction.
        state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
        state
            .iter_mut()
            .for_each(|x| *x *= x.square().square_in_place());
        mat_full_16(state);
    }
    for rc in RC16.1 {
        state[0] += rc;
        state[0] *= state[0].square().square_in_place();
        mat_partial_16(state);
    }
    for rc in RC16.2 {
        state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
        state
            .iter_mut()
            .for_each(|x| *x *= x.square().square_in_place());
        mat_full_16(state);
    }
}

pub fn mat_full_3(state: &mut [Fr; 3]) {
    // Matrix circ(2, 1, 1)
    let sum: Fr = state.iter().sum();
    state.iter_mut().for_each(|s| *s += sum);
}

pub fn mat_full_4(state: &mut [Fr; 4]) {
    let t0 = state[0] + state[1];
    let t1 = state[2] + state[3];
    let t2 = state[1].double() + t1;
    let t3 = state[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

pub fn mat_full_16(state: &mut [Fr; 16]) {
    // TODO: Use array_chunks_mut when it is stable
    let mut sum = [Fr::ZERO; 4];
    state.chunks_exact_mut(4).for_each(|s| {
        let s: &mut [Fr; 4] = s.try_into().unwrap();
        mat_full_4(s);
        sum.iter_mut().zip(s.iter()).for_each(|(sum, s)| *sum += s);
    });
    state.chunks_exact_mut(4).for_each(|s| {
        let s: &mut [Fr; 4] = s.try_into().unwrap();
        s.iter_mut().zip(sum.iter()).for_each(|(s, sum)| *s += sum);
    });
}

/// Computes a 16x16 partial matrix.
/// These meet requirements set out in Poseidon2 paper.
/// Ones + Diag(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17)
// OPT: This would benefit from delayed reduction. If we do this using
// additional bits in each limb, say base 2^43 over [u64; 6], we can do
// ~six rounds before needing to propagate carries and reductions. These
// can then be done in SIMD.
pub fn mat_partial_16(state: &mut [Fr; 16]) {
    let sum: Fr = state.iter().sum();

    // 0
    state[0] = Fr::ZERO;
    // 1
    // 2
    state[2].double_in_place();
    // 3
    state[3] += state[3].double();
    // 4
    state[4].double_in_place().double_in_place();
    // 5
    state[5] += state[5].double().double_in_place();
    // 6
    state[6].double_in_place();
    state[6] += state[6].double();
    // 7
    let t = state[7];
    state[7]
        .double_in_place()
        .double_in_place()
        .double_in_place();
    state[7] -= t;
    // 8
    state[8]
        .double_in_place()
        .double_in_place()
        .double_in_place();
    // 9
    state[9] += state[9].double().double_in_place().double_in_place();
    // 10
    state[10].double_in_place();
    state[10] += state[10].double().double_in_place();
    // 11
    let t = state[11];
    state[11].double_in_place();
    state[11] += state[11].double().double_in_place();
    state[11] += t;
    // 13
    let t1 = state[12];
    state[12].double_in_place();
    let t2 = state[12];
    state[12]
        .double_in_place()
        .double_in_place()
        .double_in_place();
    state[12] -= t1;
    state[12] -= t2;
    // 14
    state[13].double_in_place();
    let t2 = state[13];
    state[13]
        .double_in_place()
        .double_in_place()
        .double_in_place();
    state[13] -= t2;
    // 16
    state[14]
        .double_in_place()
        .double_in_place()
        .double_in_place()
        .double_in_place();
    // 17
    let t = state[15];
    state[15]
        .double_in_place()
        .double_in_place()
        .double_in_place()
        .double_in_place();
    state[15] += t;

    state.iter_mut().for_each(|s| *s += sum);
}

#[cfg(test)]
mod test {
    use {
        super::*,
        ark_ff::{BigInteger, MontFp, PrimeField},
        hex,
        std::array,
    };

    #[test]
    fn assert_hardcoded_field() {
        assert_eq!(
            hex::encode(Fr::MODULUS.to_bytes_be()),
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
        );
    }

    #[test]
    fn test_testvector_3() {
        let mut state = array::from_fn(|i| Fr::from(i as u64));
        permute_3(&mut state);
        assert_eq!(state, [
            MontFp!("5297208644449048816064511434384511824916970985131888684874823260532015509555"),
            MontFp!(
                "21816030159894113985964609355246484851575571273661473159848781012394295965040"
            ),
            MontFp!(
                "13940986381491601233448981668101586453321811870310341844570924906201623195336"
            ),
        ]);
    }

    #[test]
    fn test_vector_16() {
        // Test vector from <https://github.com/HorizenLabs/poseidon2/blob/bb476b9ca38198cf5092487283c8b8c5d4317c4e/poseidon2_rust_params.sage>
        let mut state = array::from_fn(|i| Fr::from(i as u64));
        permute_16(&mut state);
        assert_eq!(state, [
            MontFp!("7913381039332130239696391099451993335431181984785002668304949494341223775274"),
            MontFp!(
                "13114653827862491802574904733838965281638599136692207397625218937112857111034"
            ),
            MontFp!("5260853315038320427224620415642584677122388717694035179209277980943813780924"),
            MontFp!("7095024045008646205239214300853055797853073914974523849403489586109304674318"),
            MontFp!(
                "11664126658871199607513817593804851005031659127482990910815038911508774317102"
            ),
            MontFp!(
                "21691268210223129298713399970686330714477903121168305788892425830857815420367"
            ),
            MontFp!(
                "15407749918419823821950514932508821086098597396159344284212197839468132459424"
            ),
            MontFp!("3700132805016741054511056287749681800817432409246278104503824118777934690609"),
            MontFp!(
                "13475608459764345682938188282460443165916896876560315420064665395458277714687"
            ),
            MontFp!(
                "18987216660139014734696038650605544213230472335532851371054548844179055634758"
            ),
            MontFp!(
                "17098838082363265763018775191456472278582317688982731800988108801795688061056"
            ),
            MontFp!("3704449316190953774036093128903455108907706865492001018359052264170727740578"),
            MontFp!("8303990102165258148989759595771034397853874952332156771392628127282197656348"),
            MontFp!(
                "18627657396274070742089584793052815672287729224897005011410297740742199191244"
            ),
            MontFp!("6607980408076394938800075571563852892263752584185562986216463830821958103371"),
            MontFp!(
                "12353300117943495010938017401947409192192248445045039923330878007229549978485"
            ),
        ]);
    }

    #[test]
    fn test_vector_compress_100() {
        let input: [Fr; 100] = array::from_fn(|i| Fr::from(i as u64));
        eprintln!("{}", compress(&input));
        assert_eq!(
            compress(&input),
            MontFp!(
                "12499924002878240429854338251741815095221048573818181736189831611992454862386"
            ),
        )
    }

    #[test]
    fn test_vector_compress_10000() {
        let input: [Fr; 10_000] = array::from_fn(|i| Fr::from(i as u64));
        eprintln!("{}", compress(&input));
        assert_eq!(
            compress(&input),
            MontFp!(
                "14886603848044981475714290163318647373226509781142547401218185586086586147802"
            ),
        )
    }
}
