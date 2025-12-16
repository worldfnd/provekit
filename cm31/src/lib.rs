/// When modifying this file, rerun with Kani
use std::ops::{Add, Mul, Neg, Shl, Sub};

#[derive(Copy, Clone)]
struct M31I<T>(T);

trait Reduce {
    fn reduce_u32(&self) -> M31I<u32>;
    // Assumes >= 62 bits representation, "enforced" by the allowed trait
    // implementations. And also not being i32.
    fn full_reduce(&self) -> u32;
}

// Working with two redundant forms i64 and u32
// i64 to deal with subtractions
// u32 for storage, i32 is not interesting as we want to be able to add two 31
// bits values together. i32 would only allow for a subtraction.
// internally u64 is also used

// For unsigned value smaller than 61 bits conversion to i64 is problem free

// i signifies two complement form
// u signifies valid one complement form.
// for unsigned integers two complement and one complement is the same. Which
// means that conversion back and forth can be done. Whenever i is used we can
// expect the value to be negative so it first needs to be converted to
// one-complement form before reduction. That is why u64 exist internally. And
// why after reduction we move back to i64 again.
//
// i32 signifies fully reduced but that should maybe not be inside a M31, but
// just be a i32 return. i32 signifying that the upper bit is not used.

impl Reduce for M31I<i64> {
    // Assumes bits(hi) < 31
    // Safety: this should only be called on M31I<u64> whose range is [61:0] with
    // the top bits zero.
    // The only way the upper bits can be set is due to additions. After a
    // multiplication will go to 34 bits.
    #[inline(always)]
    fn reduce_u32(&self) -> M31I<u32> {
        // TODO add debug assertion for top bits
        // these operations are only intended for kernel
        let reduced = reduce(one_complement(self.0)) as u32;
        M31I(reduced)
    }

    #[inline(always)]
    fn full_reduce(&self) -> u32 {
        // Only need two rounds to fully reduce down
        let tmp = self.reduce_u32().0;
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        // branch should become CSEL
        if tmp == ((1 << 31) - 1) {
            0
        } else {
            tmp
        }
    }
}

// u32 is mostly for storage. Staying within u32 has no benefit on 64 bit
// machines
impl Reduce for M31I<u32> {
    #[inline(always)]
    fn reduce_u32(&self) -> M31I<u32> {
        *self
    }

    #[inline(always)]
    fn full_reduce(&self) -> u32 {
        let tmp = self.0;
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        // branch should become CSEL
        if tmp == ((1 << 31) - 1) {
            0
        } else {
            tmp
        }
    }
}

// switching between i64 and u64 because of the sign shift.

// After multiplication this can use the full range.
// When coming from one complement this is u32.
// Output bits
// max(lo, hi) + 1
// where lo max 31 bits and hi max 33 bits
// so maximum is 34 bits
#[inline(always)]
fn reduce(r: u64) -> i64 {
    // What are the precedence rules for shift?
    // Three cheap operations mask, shift, addition
    let lo = r & ((1 << 31) - 1);
    let hi = r >> 31;
    (hi + lo) as i64
}

// Other option is to keep everything in unsigned and only do on complement on
// subtraction and negation. That however would requiring three operations. not,
// and, add instead of just sub.

// i64 signed representation taking full 64 bits
// u64 one complement representation. By going to one complement we have a valid
// mersenne number. So it actually does two things.
// It can potentially take up 64 bits but those will all be over. It works
// because we work on a Once in one complement form you can go back and forward
// between the two representations. But not when it's in two complement.

// limit to 62 bits otherwise two reduction steps need to be done.
// implicitly says that the result we take in is two complement
fn one_complement(r: i64) -> u64 {
    // A shift of 61 and 62 might look strange at first, but that is because in
    // contrary to other shifting operations there is no splitting into an upper
    // and lower part. It's just for checking the MSB and perform an operation
    // basedon that.

    // Would checking the N-flag
    // be better? Does the compiler do this optimisation?
    // Relies on the *arithmic* shift left to maintain the sign.
    let sign = r >> 61;
    // Turn into one complement and clear out the top two bits. These top bits would
    // lead to wrong calculations as we only do not contain any information.
    ((r + sign) & ((1 << 62) - 1)) as u64
}

// The following traits are to make working with M31 across different
// representation easier.
// On ARM64 conversion from u32 to i64 is free as a u32 already takes up a full
// 64 bit register.
// Monomorphisation should optimise out when the reductions is
// not needed.

// M31I<i64> and M31I<u32> are split up becaues rust otherwise requires a dyn
// which would break monomorphisation.
impl<T: Reduce> Mul<T> for M31I<i64> {
    type Output = M31I<i64>;

    #[inline(always)]
    fn mul(self, rhs: T) -> Self::Output {
        let lhs = self.reduce_u32();
        lhs * rhs
    }
}

impl<T: Reduce> Mul<T> for M31I<u32> {
    type Output = M31I<i64>;

    // Mul returns a partial reduced to 34 bits as to only have to do a single
    // round.
    #[inline(always)]
    fn mul(self, rhs: T) -> Self::Output {
        let lhs = self;
        let rhs = rhs.reduce_u32();
        let res = lhs.0 as u64 * rhs.0 as u64;
        // After reduction 34 bits
        M31I(reduce(res))
    }
}

impl<T: Into<i64>, K: Into<i64>> Sub<M31I<T>> for M31I<K> {
    type Output = M31I<i64>;

    fn sub(self, rhs: M31I<T>) -> Self::Output {
        M31I(self.0.into() - rhs.0.into())
    }
}

impl<T: Into<i64>, K: Into<i64>> Add<M31I<T>> for M31I<K> {
    type Output = M31I<i64>;

    fn add(self, rhs: M31I<T>) -> Self::Output {
        M31I(self.0.into() + rhs.0.into())
    }
}

// TODO implement shift left
impl<K: Into<i64>> Shl<u8> for M31I<K> {
    type Output = M31I<i64>;

    fn shl(self, rhs: u8) -> Self::Output {
        M31I(self.0.into() << rhs)
    }
}

#[cfg(kani)]
mod verification {
    use crate::{reduce, Reduce, M31I};
    // Takes a 62bit number and sign extends it into a valid i64
    fn sign_extend(x: u64) -> i64 {
        let sign = x >> 61;
        let sign = sign << 2 | sign << 1 | sign;
        ((sign << 61) | x) as i64
    }

    #[kani::proof]
    fn reduce_i64() {
        let x: u64 = kani::any::<u64>() & ((1 << 62) - 1);
        let x = sign_extend(x);
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, M31I(x).full_reduce())
    }

    // The proof for the multiplier is too slow. Therefore we model check the inner
    // part. The input slightly larger than what it would be within the multiplier.
    #[kani::proof]
    fn reduce_u64() {
        let x: u64 = kani::any::<u64>();
        assert_eq!(
            x.rem_euclid((1 << 31) - 1) as u32,
            M31I(reduce(x)).full_reduce()
        )
    }

    // Checking the reduction of i64 is not enough as it will not cover the full
    // range of u32. Other libraries use
    #[kani::proof]
    fn reduce_u32() {
        let x = kani::any::<u32>();
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, M31I(x).full_reduce())
    }
}
