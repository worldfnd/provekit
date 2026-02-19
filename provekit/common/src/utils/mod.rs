// pub mod file_io;
mod print_abi;
pub mod serde_ark;
pub mod serde_ark_option;
pub mod serde_ark_vec;
pub mod serde_hex;
pub mod serde_jsonify;
pub mod sumcheck;
pub mod zk_utils;

pub use self::print_abi::PrintAbi;
use {
    crate::{FieldElement, NoirElement},
    ark_ff::{BigInt, Field, PrimeField},
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
pub fn pad_to_power_of_two<T: Default>(mut witness: Vec<T>) -> Vec<T> {
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

/// Computes multiplicative inverses using Montgomery's batch inversion trick.
///
/// Reduces N field inversions to 1 inversion + 3N multiplications.
/// See: <https://encrypt.a41.io/primitives/abstract-algebra/group/batch-inverse>
pub fn batch_inverse_montgomery(values: &[FieldElement]) -> Vec<FieldElement> {
    let batch_size = values.len();
    if batch_size == 0 {
        return Vec::new();
    }

    if batch_size == 1 {
        return vec![values[0].inverse().expect("Cannot invert zero")];
    }

    // Forward pass: compute prefix products
    let mut prefix = Vec::with_capacity(batch_size);
    let mut acc = FieldElement::from(1u32);
    for &v in values {
        acc *= v;
        prefix.push(acc);
    }

    // Invert the total product (single expensive operation)
    let mut inv_acc = prefix[batch_size - 1]
        .inverse()
        .expect("Batch inversion: zero product");

    // Backward pass: compute individual inverses
    let mut inverses = vec![FieldElement::from(0u32); batch_size];
    for i in (1..batch_size).rev() {
        inverses[i] = inv_acc * prefix[i - 1];
        inv_acc *= values[i];
    }
    inverses[0] = inv_acc;

    inverses
}

#[cfg(feature = "mavros_compiler")]
pub fn convert_mavros_r1cs_to_provekit(
    mavros_r1cs: &mavros_artifacts::R1CS,
) -> crate::R1CS {
    let num_witnesses = mavros_r1cs.witness_layout.size();
    let num_constraints = mavros_r1cs.constraints.len();

    let total_entries: usize = mavros_r1cs
        .constraints
        .iter()
        .map(|c| c.a.len() + c.b.len() + c.c.len())
        .sum();

    let mut r1cs = crate::R1CS::new();
    r1cs.add_witnesses(num_witnesses);
    r1cs.reserve_constraints(num_constraints, total_entries);

    let mut a_buf: Vec<(u32, crate::InternedFieldElement)> = Vec::with_capacity(64);
    let mut b_buf: Vec<(u32, crate::InternedFieldElement)> = Vec::with_capacity(64);
    let mut c_buf: Vec<(u32, crate::InternedFieldElement)> = Vec::with_capacity(64);

    for constraint in &mavros_r1cs.constraints {
        a_buf.clear();
        a_buf.extend(
            constraint
                .a
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        b_buf.clear();
        b_buf.extend(
            constraint
                .b
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        c_buf.clear();
        c_buf.extend(
            constraint
                .c
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        r1cs.push_constraint(
            a_buf.iter().copied(),
            b_buf.iter().copied(),
            c_buf.iter().copied(),
        );
    }

    r1cs
}
