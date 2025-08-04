pub mod file_io;
mod print_abi;
pub mod serde_ark;
pub mod serde_ark_option;
pub mod serde_hex;
pub mod serde_jsonify;
pub mod sumcheck;
pub mod zk_utils;

use file_vec::FileVec;
pub use self::print_abi::PrintAbi;
use {
    crate::{FieldElement, NoirElement},
    ark_ff::{BigInt, PrimeField},
    ruint::{aliases::U256, uint},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        mem::MaybeUninit,
    },
    tracing::instrument,
};

/// 1/2 for the BN254
pub const HALF: FieldElement = uint_to_field(uint!(
    10944121435919637611123202872628637544274182200208017171849102093287904247809_U256
));

/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// Unzip a [[(T,T); N]; M] into ([[T; N]; M],[[T; N]; M]) using move semantics
// TODO: Cleanup when <https://github.com/rust-lang/rust/issues/96097> lands
#[allow(unsafe_code)] // Required for `MaybeUninit`
fn unzip_double_array<T: Sized, const N: usize, const M: usize>(
    input: [[(T, T); N]; M],
) -> ([[T; N]; M], [[T; N]; M]) {
    // Create uninitialized memory for the output arrays
    let mut left: [[MaybeUninit<T>; N]; M] = [const { [const { MaybeUninit::uninit() }; N] }; M];
    let mut right: [[MaybeUninit<T>; N]; M] = [const { [const { MaybeUninit::uninit() }; N] }; M];

    // Move results to output arrays
    for (i, a) in input.into_iter().enumerate() {
        for (j, (l, r)) in a.into_iter().enumerate() {
            left[i][j] = MaybeUninit::new(l);
            right[i][j] = MaybeUninit::new(r);
        }
    }

    // Convert the arrays of MaybeUninit into fully initialized arrays
    // Safety: All the elements have been initialized above
    let left = left.map(|a| a.map(|u| unsafe { u.assume_init() }));
    let right = right.map(|a| a.map(|u| unsafe { u.assume_init() }));
    (left, right)
}

pub const fn uint_to_field(i: U256) -> FieldElement {
    FieldElement::new(BigInt(i.into_limbs()))
}

/// Convert a Noir field element to a native `FieldElement`
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}

/// Calculates the degree of the next smallest power of two
pub const fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}

/// Pads the vector with 0 so that the number of elements in the vector is a
/// power of 2
#[instrument(skip_all)]
pub fn pad_to_power_of_two<T: Default>(mut witness: FileVec<T>) -> FileVec<T> {
    let target_len = 1 << next_power_of_two(witness.len());
    witness.reserve_exact(target_len - witness.len());
    while witness.len() < target_len {
        witness.push(T::default());
    }
    witness
}

/// Pretty print a float using SI-prefixes.
#[must_use]
pub fn human(value: f64) -> impl Display {
    struct Human(f64);
    impl Display for Human {
        fn fmt(&self, f: &mut Formatter) -> FmtResult {
            let log10 = if self.0.is_normal() {
                self.0.abs().log10()
            } else {
                0.0
            };
            let si_power = ((log10 / 3.0).floor() as isize).clamp(-10, 10);
            let value = self.0 * 10_f64.powi((-si_power * 3) as i32);
            let digits =
                f.precision().unwrap_or(3) - 1 - 3.0f64.mul_add(-(si_power as f64), log10) as usize;
            let separator = if f.alternate() { "" } else { "\u{202F}" };
            if f.width() == Some(6) && digits == 0 {
                write!(f, " ")?;
            }
            write!(f, "{value:.digits$}{separator}")?;
            let suffix = "qryzafpnμm kMGTPEZYRQ"
                .chars()
                .nth((si_power + 10) as usize)
                .unwrap();
            if suffix != ' ' || f.width() == Some(6) {
                write!(f, "{suffix}")?;
            }
            Ok(())
        }
    }
    Human(value)
}
