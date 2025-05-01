use std::array;

use quickcheck::Arbitrary;

pub const MASK52: u64 = 2_u64.pow(52) - 1;
pub const MASK48: u64 = 2_u64.pow(48) - 1;

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct U256b64(pub [u64; 4]);
#[derive(PartialEq, Clone, Copy, Debug)]
pub struct U256b52(pub [u64; 5]);

impl From<U256b64> for U256b52 {
    fn from(u: U256b64) -> Self {
        let U256b64(limbs) = u;
        let [l0, l1, l2, l3] = limbs;
        U256b52([
            l0 & MASK52,
            ((l0 >> 52) | (l1 << 12)) & MASK52,
            ((l1 >> 40) | (l2 << 24)) & MASK52,
            ((l2 >> 28) | (l3 << 36)) & MASK52,
            l3 >> 16,
        ])
    }
}

impl From<U256b52> for U256b64 {
    fn from(u: U256b52) -> Self {
        let U256b52(limbs) = u;
        let [l0, l1, l2, l3, l4] = limbs;
        U256b64([
            l0 | (l1 << 52),
            ((l1 >> 12) | (l2 << 40)),
            ((l2 >> 24) | (l3 << 28)),
            ((l3 >> 36) | (l4 << 16)),
        ])
    }
}

impl Arbitrary for U256b52 {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut inner = array::from_fn(|_| u64::arbitrary(g) & MASK52);
        inner[4] = inner[4] & MASK48;
        U256b52(inner)
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(shrink(self.0).map(U256b52))
    }
}

fn shrink<const N: usize>(a: [u64; N]) -> Box<dyn Iterator<Item = [u64; N]>> {
    if a.iter().all(|&ai| ai == 0) {
        return Box::new(std::iter::empty());
    }

    // Create vector of shrunk values
    let mut shrunk = Vec::new();

    // Add zero as the smallest possible value
    shrunk.push([0; N]);

    for (i, &elem) in a.iter().enumerate() {
        if elem != 0 {
            let mut zero_limb = a.clone();
            zero_limb[i] = 0;
            let mut half_limb = a.clone();
            half_limb[i] = elem >> 1;
            shrunk.push(zero_limb);
            shrunk.push(half_limb);
        }
    }

    Box::new(shrunk.into_iter())
}

impl Arbitrary for U256b64 {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        U256b64(array::from_fn(|_| u64::arbitrary(g)))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(shrink(self.0).map(U256b64))
    }
}

#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;

    use super::{U256b52, U256b64};

    #[quickcheck]
    fn conv64_52(a: U256b64) -> bool {
        let converted = U256b52::from(a);
        let reconverted = U256b64::from(converted);

        a == reconverted
    }

    #[quickcheck]
    fn conv52_64(a: U256b52) -> bool {
        let converted = U256b64::from(a);
        let reconverted = U256b52::from(converted);

        a == reconverted
    }
}
