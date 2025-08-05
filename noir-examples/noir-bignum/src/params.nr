use super::constants::{LIMB_SIZE, TWO_POW_32};

pub struct BigNumParams<let N: u32, let MOD_BITS: u32> {
    pub has_multiplicative_inverse: bool,

    // @brief modulus: all BigNum operations are evaluated modulo this value
    pub modulus: [u64; N],

    // @brief double_modulus: used when performing negations and subtractions
    // @note we borrow 1 from the last limb. This is for easing up the operations that might underflow
    pub double_modulus: [u64; N],

    // @brief redc_param used for __barrett_reduction. See https://en.wikipedia.org/wiki/Barrett_reduction
    pub redc_param: [u64; N],
}

// To be implemented by the user for any BigNum they define, or within the predefined BigNums in the `fields/` dir.
pub trait BigNumParamsGetter<let N: u32, let MOD_BITS: u32> {
    fn get_params() -> BigNumParams<N, MOD_BITS>;
}

impl<let N: u32, let MOD_BITS: u32> BigNumParams<N, MOD_BITS> {
    pub fn new(has_multiplicative_inverse: bool, modulus: [u64; N], redc_param: [u64; N]) -> Self {
        Self {
            has_multiplicative_inverse,
            modulus,
            double_modulus: get_double_modulus(modulus),
            redc_param,
        }
    }
}

impl<let N: u32, let MOD_BITS: u32> std::cmp::Eq for BigNumParams<N, MOD_BITS> {
    fn eq(self, other: Self) -> bool {
        (self.has_multiplicative_inverse == other.has_multiplicative_inverse)
            & (self.modulus == other.modulus)
            & (self.double_modulus == other.double_modulus)
            & (self.redc_param == other.redc_param)
    }
}

fn get_double_modulus<let N: u32>(modulus: [u64; N]) -> [u64; N] {
    let mut result: [u64; N] = [0; N];
    let mut carry: u64 = 0;
    for i in 0..N {
        let mut add_term = (modulus[i] + modulus[i] + carry);
        carry = add_term >> (LIMB_SIZE as u8);
        add_term = add_term - (carry << (LIMB_SIZE as u8));
        result[i] = add_term;
    }

    result[0] += TWO_POW_32;
    for i in 1..N - 1 {
        result[i] += (TWO_POW_32 - 1);
    }
    result[N - 1] -= 1;
    result
}
