use crate::constants::{self, U64_2P};

/// Macro to extract a subarray from an array.
///
/// # Arguments
///
/// * `$t` - The source array
/// * `$b` - The starting index (base) in the source array
/// * `$l` - The length of the subarray to extract
///
/// This should be used over t[N..].try_into().unwrap() in getting a subarray.
/// Using try_into+unwrap introduces the eh_personality (exception handling)
///
/// # Example
///
/// ```
/// use bn254_multiplier::subarray;
/// let array = [1, 2, 3, 4, 5];
/// let sub = subarray!(array, 1, 3); // Creates [2, 3, 4]
/// ```
#[macro_export]
macro_rules! subarray {

    ($t:expr, $b: literal, $l: literal) => {
        {
        use seq_macro::seq;
        let t = $t;
        let mut s = [0;$l];

        // The compiler does not detect out-of-bounds when using `for` therefore `seq!` is used here
        seq!(i in 0..$l {
            s[i] = t[$b+i];
        });
        s
    }
    };
}

#[inline(always)]
pub fn addv<const N: usize>(mut a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut carry = 0u64;
    for i in 0..N {
        let (sum1, overflow1) = a[i].overflowing_add(b[i]);
        let (sum2, overflow2) = sum1.overflowing_add(carry);
        a[i] = sum2;
        carry = (overflow1 as u64) + (overflow2 as u64);
    }
    a
}

#[inline(always)]
pub fn reduce_ct(a: [u64; 4]) -> [u64; 4] {
    let b = [[0_u64; 4], U64_2P];
    let msb = (a[3] >> 63) & 1;
    sub(a, b[msb as usize])
}

#[inline(always)]
pub fn sub<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut borrow: i128 = 0;
    let mut c = [0; N];
    for i in 0..N {
        let tmp = a[i] as i128 - b[i] as i128 + borrow;
        c[i] = tmp as u64;
        borrow = tmp >> 64
    }
    c
}

#[inline(always)]
// Based on ark-ff
// On WASM first doing a widening on the operands will cause __multi3 called
// which is u128xu128 -> u128 causing unnecessary multiplications
pub const fn widening_mul(a: u64, b: u64) -> u128 {
    #[cfg(not(target_family = "wasm"))]
    {
        a as u128 * b as u128
    }
    #[cfg(target_family = "wasm")]
    {
        let a0 = a as u32 as u64;
        let a1 = a >> 32;
        let b0 = b as u32 as u64;
        let b1 = b >> 32;

        let c00 = (a0 * b0) as u128;
        let c01 = (a0 * b1) as u128;
        let c10 = (a1 * b0) as u128;
        let cxx = (c01 + c10) << 32;
        let c11 = ((a1 * b1) as u128) << 64;
        (c00 | c11) + cxx
    }
}

#[inline(always)]
pub const fn carrying_mul_add(a: u64, b: u64, add: u64, carry: u64) -> (u64, u64) {
    let c: u128 = widening_mul(a, b) + carry as u128 + add as u128;
    (c as u64, (c >> 64) as u64)
}

/// Precomputed magic constants for fast approximate floor division by the
/// BN254 prime P, following Warren's "Hacker's Delight" (integer division by
/// constants). Guarantees `div_p(val) ≤ ⌊val / P⌋` for all inputs within the
/// declared bit range.
pub struct MulShift {
    mul:   u64,
    shift: u32,
}

impl MulShift {
    /// Computes magic multiplication and shift constants for approximate floor
    /// division by P, such that `div_p(val) ≤ ⌊val / P⌋` for all `val` within
    /// `max_bit_size` bits. `precision` controls how many of the top bits of
    /// `val` are used — higher precision yields a tighter approximation.
    pub const fn new(max_bit_size: u32, precision: u32) -> Self {
        // Generate magic numbers for division by bn254's prime for a range of top-bit
        // widths.

        // Based on Warren's "Hacker's Delight" (integer
        // division by constants) to find a magic multiplier for each bit-width.

        use crate::constants::U64_P;

        let d = (U64_P[3] >> (max_bit_size - 192 - precision)) + 1; // d = divisor = ceil(p / 2^(max_bit_size-w))
        let nc = 2_u64.pow(precision) - 1 - (2_u64.pow(precision) % d); // nc = largest value s.t. nc mod d == d-1
        let mut s = precision; // start at precision; s < precision values are skipped
        let m;
        loop {
            // s = shift exponent
            if 2_u64.pow(s) > nc * (d - 1 - (2_u64.pow(s) - 1) % d) {
                m = (2_u64.pow(s) + d - 1 - (2_u64.pow(s) - 1) % d) / d; // m = magic multiplier
                break;
            }
            s += 1;
            assert!(s < 64, "no magic multiplier found");
        }

        MulShift { mul: m, shift: s }
    }

    #[inline(always)]
    /// Returns an under-approximation of ⌊val / P⌋ (result ≤ true quotient).
    /// `val` must fit within the `max_bit_size` passed to [`MulShift::new`].
    pub const fn div_p(&self, val: u64) -> u64 {
        // assumes systems can handle multiplication by 64 bits without performance
        // penalty.
        (val * self.mul) >> self.shift
    }
}

/// Approximate floor division by P using the upper 6 bits of `x`.
/// `x` must be the upper limb of a u256 in 64-bit radix.
///
/// Returns a value ≤ ⌊x / P⌋. This is the most precise
/// approximation achievable without multiplication on ARM64 and x86.
///
/// Tradeoff: due the limited range of this division \[0,4\] (instead of \[0,5\]
/// for u256) will lead to a larger value after subtraction reduction.
/// subtraction reduction output: [0, 1+ε] with ε < 0.3.
#[inline(always)]
pub fn div_p_6b(x: u64) -> u64 {
    let upper_bits = x >> (64 - 6);
    // const to force compile time evaluation
    const MULSHIFT: MulShift = MulShift::new(256, 6);
    MULSHIFT.div_p(upper_bits)
}

/// Approximate floor division by P using the upper 32 bits of `x`.
/// `x` must be the upper limb of a u256 in 64-bit radix.
///
/// Returns a value ≤ ⌊x / P⌋. This is the most precise
/// approximation achievable with a 32bx32b->64b multiplier.
#[inline(always)]
pub fn div_p_32b(x: u64) -> u64 {
    let upper_bits = x >> (64 - 32);
    // const to force compile time evaluation
    const MULSHIFT: MulShift = MulShift::new(256, 32);
    MULSHIFT.div_p(upper_bits)
}

/// Subtracts an approximate multiple of P from `x` using `div_p` on the high
/// limb.
///
/// The result is not fully reduced; the output range depends on the precision
/// of the supplied `div_p` — see [`div_p_6b`] and [`div_p_32b`].
#[inline(always)]
pub fn subtraction_reduce<F: Fn(u64) -> u64>(div_p: F, x: [u64; 4]) -> [u64; 4] {
    // No clamping as the max value of x can't go past 5. Which is the maximum of
    // the table.
    let q = div_p(x[3]) as usize;
    sub(x, constants::U64_P_MULTIPLES[q])
}

#[cfg(kani)]
mod proofs {
    use {
        super::{constants::U64_2P, div_p_32b, div_p_6b},
        crate::constants::U64_P_MULTIPLES,
    };

    /// Lexicographic ≤ on little-endian 256-bit integers.
    fn le256(a: [u64; 4], b: [u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    /// TODO: tighter bounds
    #[kani::proof]
    fn div_p_32b_underapprox() {
        let x: u64 = kani::any();
        let q = div_p_32b(x);

        let r = U64_P_MULTIPLES[q as usize][3];
        assert!(x >= r);
        assert!(le256([0, 0, 0, x - r], U64_2P));
    }

    #[kani::proof]
    // TODO tighter bounds
    fn div_p_6b_underapprox() {
        let x: u64 = kani::any();
        let q = div_p_6b(x);

        let r = U64_P_MULTIPLES[q as usize][3];
        assert!(x >= r);
        assert!(le256([0, 0, 0, x - r], U64_2P));
    }
}
