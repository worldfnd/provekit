//! [`ruint`] backend for [`ModRing`]

use {
    super::{ModRing, UintMont},
    ruint::{aliases::U64, Uint},
};

impl<const BITS: usize, const LIMBS: usize> UintMont for Uint<BITS, LIMBS> {
    fn parameters_from_modulus(modulus: Self) -> ModRing<Self> {
        let mod_inv = U64::wrapping_from(modulus)
            .inv_ring()
            .expect("Modulus not an odd positive integer.")
            .wrapping_neg()
            .to();

        // R = 2^BITS mod modulus.
        let montgomery_r = Self::from(2).pow_mod(Self::from(Self::BITS), modulus);
        let montgomery_r2 = montgomery_r.mul_mod(montgomery_r, modulus);
        let montgomery_r3 = montgomery_r2.mul_redc(montgomery_r2, modulus, mod_inv);
        ModRing {
            modulus,
            mod_inv,
            montgomery_r,
            montgomery_r2,
            montgomery_r3,
        }
    }

    fn random<R: rand::Rng + ?Sized>(rng: &mut R, max: Self) -> Self {
        let mut result = Self::ZERO;
        unsafe { // TODO: Update rand crate,
            for limb in  result.as_limbs_mut() {
                *limb = rng.gen();
            }
        }
        result %= max;
        result
    }

    #[inline]
    fn mul_redc(self, other: Self, modulus: Self, mod_inv: u64) -> Self {
        Uint::mul_redc(self, other, modulus, mod_inv)
    }

    #[inline]
    fn square_redc(self, modulus: Self, mod_inv: u64) -> Self {
        Uint::square_redc(self, modulus, mod_inv)
    }

    #[inline]
    fn add_mod(self, other: Self, modulus: Self) -> Self {
        let (sum, carry) = self.overflowing_add(other);
        let (reduced, borrow) = sum.overflowing_sub(modulus);
        if carry || !borrow {
            reduced
        } else {
            sum
        }
    }

    #[inline]
    fn inv_mod(self, modulus: Self) -> Option<Self> {
        Uint::inv_mod(self, modulus)
    }
}
