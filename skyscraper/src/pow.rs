use {
    crate::{arithmetic::less_than, simple::compress, WIDTH_LCM},
    ark_ff::Zero,
    core::{
        array,
        sync::atomic::{AtomicU64, Ordering},
    },
    rayon,
    zerocopy::IntoBytes as _,
};

const PROVER_BIAS: f64 = 0.01;

/// Returns a threshold for a given security target in bits.
///
/// The probability that a uniform random element from the field is less than
/// the threshold is at least 2 ^ -difficulty. i.e.:
///
/// |{x:F | x < threshold}| / |F| < 2^-difficulty
pub fn threshold(difficulty: f64) -> [u64; 4] {
    assert!(
        (0.0..80.0).contains(&difficulty),
        "Difficulty must be in the range [0, 80)"
    );
    let modulus = (crate::constants::MODULUS[1][3] as f64) * 2.0f64.powi(192);
    let prob = (-difficulty).exp2();
    f64_to_u256(prob * modulus)
}

pub fn verify(challenge: [u64; 4], difficulty: f64, nonce: u64) -> bool {
    difficulty.is_zero() || less_than(compress(challenge, [nonce, 0, 0, 0]), threshold(difficulty))
}

/// Multi-threaded proof of work solver.
///
/// It will add a slight bias to the difficulty to make sure the prover
/// threshold is higher than the verifier threshold and there are not rounding
/// issues affecting completeness.
pub fn solve(challenge: [u64; 4], difficulty: f64) -> u64 {
    const WIDTH: usize = WIDTH_LCM * 10;
    if difficulty.is_zero() {
        return 0;
    }
    let threshold = threshold(difficulty + PROVER_BIAS);
    let compress_many = crate::block4::compress_many; // TODO: autotune
    let best = AtomicU64::new(u64::MAX);
    rayon::broadcast(|ctx| {
        let mut input: [[[u64; 4]; 2]; WIDTH] = array::from_fn(|_| [challenge, [0; 4]]);
        let mut hashes = [[0_u64; 4]; WIDTH];

        // Find the thread specific subset of nonces
        for nonce in (0..)
            .step_by(WIDTH)
            .skip(ctx.index())
            .step_by(ctx.num_threads())
        {
            // Stop if another thread found a better solution
            if nonce > best.load(Ordering::Acquire) {
                return;
            }
            for i in 0..WIDTH {
                input[i][1][0] = nonce + i as u64;
            }
            compress_many(input.as_bytes(), hashes.as_mut_bytes());
            for i in 0..WIDTH {
                if less_than(hashes[i], threshold) {
                    best.fetch_min(nonce + i as u64, Ordering::AcqRel);
                    return;
                }
            }
        }
    });
    let nonce = best.load(Ordering::Acquire);
    debug_assert!(verify(challenge, difficulty, nonce));
    nonce
}

/// Returns sign, exponent and significand of an `f64`
///
/// The significand has the implicit leading one added for normal floats.
fn f64_parts(f: f64) -> (bool, i16, u64) {
    let bits = f.to_bits();
    let sign = (bits >> 63) != 0;
    let exp_bits = ((bits >> 52) & 0x7ff) as i16;
    let frac = bits & ((1 << 52) - 1);
    if exp_bits == 0 {
        // Subnormals and zero (no implicit 1)
        (sign, -1022, frac)
    } else {
        // Normal: add the implicit 1 at bit 52
        (sign, exp_bits - 1023, frac + (1 << 52))
    }
}

/// Convert a float to the nearest u256, clamping to zero and MAX.
fn f64_to_u256(f: f64) -> [u64; 4] {
    let (sign, exp, significand) = f64_parts(f);
    dbg!(exp, significand);
    if sign {
        return [0; 4];
    }
    if exp > 256 {
        return [u64::MAX; 4];
    }
    let mut result = [0; 4];
    let shift = exp - 52;
    if shift < 0 {
        result[0] = f.round() as u64;
    } else {
        let shift = shift as u32;
        let (limb, shift) = ((shift / 64) as usize, shift % 64);
        result[limb] = significand << shift;
        if shift != 0 && limb < 3 {
            result[limb + 1] = significand >> (64 - shift);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use {super::*, core::f64};

    #[test]
    fn test_f64_to_u256() {
        assert_eq!(f64_to_u256(0.0), [0; 4]);
        assert_eq!(f64_to_u256(f64::MIN), [0; 4]);
        assert_eq!(f64_to_u256(0.49), [0; 4]);
        assert_eq!(f64_to_u256(0.50), [1, 0, 0, 0]);
        assert_eq!(f64_to_u256(1.0), [1, 0, 0, 0]);
        assert_eq!(f64_to_u256(2.0_f64.powi(128)), [0, 0, 1, 0]);
        assert_eq!(f64_to_u256(f64::INFINITY), [u64::MAX; 4]);
        assert_eq!(f64_to_u256(-42.0), [0; 4]);
        assert_eq!(
            f64_to_u256(f64::from_bits(0x7ff0000000000001)),
            [u64::MAX; 4]
        ); // NaN
    }

    #[test]
    fn test_solve_verify() {
        for difficulty in [0.0_f64, f64::consts::PI] {
            let challenge = [u64::MAX; 4];
            let nonce = solve(challenge, difficulty);
            assert!(verify(challenge, difficulty, nonce));
        }
    }
}
