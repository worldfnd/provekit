const P3: u64 = 3 * (1 << 31 - 1);

// Tag can also be the internal type
// 64 byte, 32 byte, 31 byte, 31 byte zero check. De laatste twee is
// waarschijnlijk geen interessant ondersheid Aan de andere kant lijkt het geen
struct M31(u32);

// Introduce tag to track in which state the M31 is?
// State
impl M31 {
    // Needs to return a value if it's going to be tagged with the internal state.
    fn reduce_u31(&mut self) {
        let tmp = self.0;
        // TODO: mask
        let tmp = tmp >> 31 + ((tmp << 1) >> 1);
        let tmp = tmp >> 31 + ((tmp << 1) >> 1);
        self.0 = tmp;
    }
}

impl Add for M31 {
    type Output = M31;

    // 32 bit sized because otherwise there might be a masking operations
    // while adds W will zero it out.
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        // Different ways of presenting it
        // 32 bytes
        // 64 bytes
        // adds w
        let (tmp, o) = self.0.overflowing_add(rhs.0);
        // can't use adcs as it needs to be shifted first
        // so 64 bit might be better as it doesn't require moving the carry to another
        // register.
        // Interested in how the compiler takes this?
        let (tmp, o) = tmp.overflowing_add(2 * o as u32);
        let out = tmp + 2 * o as u32;

        Self(out)
    }
}

impl Sub for M31 {
    type Output = M31;

    fn sub(self, rhs: Self) -> Self::Output {
        // 33 bits + 32 bits -> 34 bits
        let tmp = P3 + self.0 as u64 - rhs.0 as u64;
        // 34 bits -> 32 bits
        let hi = (tmp >> 32) as u32;
        let lo = tmp as u32;
        Self(2 * hi + lo)
    }
}

impl Neg for M31 {
    type Output = M31;

    fn neg(self) -> Self::Output {
        let tmp = P3 - self.0 as u64;
        let hi = (tmp >> 32) as u32;
        let lo = tmp as u32;
        Self(2 * hi + lo)
    }
}

impl Mul for M31 {
    type Output = M31;

    fn mul(self, rhs: Self) -> Self::Output {
        let (lo, hi) = u32::carrying_mul_add(self.0, rhs.0, 0, 0);
        // shift addition
        // shift, shift, addition
        // 64bits -> 34 bits
        // 2 * hi -> 33 bits; 33 bits + 32 bits -> 34 bits
        let tmp = 2 * hi as u64 + lo as u64;
        // 34 bits -> 32 bits
        let hi = (tmp >> 32) as u32;
        let lo = tmp as u32;
        Self(2 * hi + lo)
    }
}

impl Shl<u8> for M31 {
    type Output = M31;

    fn shl(mut self, rhs: u8) -> Self::Output {
        self.reduce_u31();
        todo!();
    }
}
