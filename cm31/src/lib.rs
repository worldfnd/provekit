use std::ops::{Add, Mul, Neg, Shl, Sub};

struct M31I<T>(T);

impl<T: Into<u64>> Add<M31I<T>> for M31I<u64> {
    type Output = M31I<u64>;

    fn add(self, rhs: M31I<T>) -> Self::Output {
        Self(self.0 + rhs.0.into())
    }
}

trait Reduce {
    fn reduce_u32(self) -> M31I<u32>;
}

impl Reduce for M31I<u64> {
    // Assumes bits(hi) < 31
    // Safety: this should only be called on M31I<u64> whose range is [61:0] with
    // the top bits zero.
    // The only way the upper bits can be set is due to additions. After a
    // multiplication will go to 34 bits.
    fn reduce_u32(self) -> M31I<u32> {
        // TODO add debug assertion for top bits
        // these operations are only intended for kernel
        let reduced = reduce(self.0);
        M31I(reduced as u32)
    }
}

impl Reduce for M31I<u32> {
    #[inline]
    fn reduce_u32(self) -> M31I<u32> {
        self
    }
}

// Output bits
// max(lo, hi) + 1
// where lo max 31 bits and hi max 33 bits
// so maximum is 34 bits
fn reduce(r: u64) -> u64 {
    // What are the precedence rules for shift?
    // Three cheap operations mask, shift, addition
    let lo = r & ((1 << 31) - 1);
    let hi = r >> 31;
    hi + lo
}

// Might not be the right type for the multiplication in a kernel.
impl<T: Reduce> Mul<T> for M31I<u64> {
    type Output = M31I<u64>;

    fn mul(self, rhs: T) -> Self::Output {
        let lhs = self.reduce_u32();
        let rhs = rhs.reduce_u32();
        let res = lhs.0 as u64 * rhs.0 as u64;
        // After reduction 34 bits
        M31I(reduce(res))
    }
}

impl Sub for M31I<u64> {
    type Output = M31I<u64>;

    fn sub(self, rhs: Self) -> Self::Output {
        todo!()
    }
}
