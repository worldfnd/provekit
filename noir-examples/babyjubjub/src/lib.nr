// BabyJubJub Curve Implementation for Noir
// Based on EIP-2494 and Circom implementation
// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
// where a = 168700, d = 168696

use check_sub_group::esc_mul_fix_scalar;
use escalar_mul_fix::generator_mul_fix;
use std::field::bn254;

mod tests;
pub mod hash_to_curve;
pub(crate) mod montgomery;
pub(crate) mod window_table;
pub(crate) mod check_sub_group;
pub(crate) mod escalar_mul_fix;

// BabyJubJub curve constants
global BABYJUBJUB_A: Field = 168700;
global BABYJUBJUB_D: Field = 168696;

// Identity point (0, 1)
global BABYJUBJUB_IDENTITY_X: Field = 0;
global BABYJUBJUB_IDENTITY_Y: Field = 1;

global BABYJUBJUB_GENERATOR_X: Field =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
global BABYJUBJUB_GENERATOR_Y: Field =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;

// Scalar field order (Fr) - prime order of BabyJubJub's scalar field
global BABYJUBJUB_Fr: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

/// Represents a point on the BabyJubJub curve
pub struct BabyJubJubPoint {
    pub x: Field,
    pub y: Field,
}

impl BabyJubJubPoint {
    /// Creates a new BabyJubJub point
    pub fn new(x: Field, y: Field) -> Self {
        BabyJubJubPoint { x, y }
    }

    /// Creates the identity point
    pub fn identity() -> Self {
        BabyJubJubPoint { x: BABYJUBJUB_IDENTITY_X, y: BABYJUBJUB_IDENTITY_Y }
    }

    /// Creates the generator point
    pub fn generator() -> Self {
        BabyJubJubPoint { x: BABYJUBJUB_GENERATOR_X, y: BABYJUBJUB_GENERATOR_Y }
    }

    /// Checks if the point is on the BabyJubJub curve
    /// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
    pub fn is_on_curve(self) -> bool {
        let lhs = BABYJUBJUB_A * self.x * self.x + self.y * self.y;
        let rhs = 1 + BABYJUBJUB_D * self.x * self.x * self.y * self.y;
        lhs == rhs
    }

    /// Checks if the point is the identity element
    pub fn is_identity(self) -> bool {
        let x_eq = self.x == BABYJUBJUB_IDENTITY_X;
        let y_eq = self.y == BABYJUBJUB_IDENTITY_Y;
        x_eq & y_eq
    }

    /// Checks if the point is not the identity element
    pub fn is_not_identity(self) -> bool {
        !self.is_identity()
    }

    /// Multiplies the point by the cofactor (7 for BabyJubJub over BN254)
    pub fn multiply_by_cofactor(self) -> Self {
        self.double().double().double()
    }

    unconstrained fn add_unconstrained(self, other: BabyJubJubPoint) -> (Field, Field) {
        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (-BABYJUBJUB_A * self.x + self.y) * (other.x + other.y);
        let tau = beta * gamma;

        let denominator1 = 1 + BABYJUBJUB_D * tau;
        let denominator2 = 1 - BABYJUBJUB_D * tau;

        let x = (beta + gamma) / denominator1;
        let y = (delta + BABYJUBJUB_A * beta - gamma) / denominator2;
        (x, y)
    }

    /// Point addition on BabyJubJub curve
    pub fn add(self, other: BabyJubJubPoint) -> Self {
        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (-BABYJUBJUB_A * self.x + self.y) * (other.x + other.y);
        let tau = beta * gamma;

        let den_x = 1 + BABYJUBJUB_D * tau;
        let den_y = 1 - BABYJUBJUB_D * tau;

        // Safety: cast to unconstrained field
        let (x, y) = unsafe { Self::add_unconstrained(self, other) };
        assert(y * den_y == delta + BABYJUBJUB_A * beta - gamma);
        assert(x * den_x == beta + gamma);

        BabyJubJubPoint { x, y }
    }

    /// Point negation
    pub fn negate(self) -> Self {
        BabyJubJubPoint { x: -self.x, y: self.y }
    }

    /// Point subtraction: self - other = self + (-other)
    pub fn subtract(self, other: BabyJubJubPoint) -> Self {
        self.add(other.negate())
    }

    /// Point doubling
    pub fn double(self) -> Self {
        self.add(self)
    }

    pub fn scalar_mul(self, scalar: Field) -> Self {
        // Early termination for zero scalar
        if scalar == 0 {
            BabyJubJubPoint::identity()
        } else {
            // Decompose scalar into 251 bits (BabyJubJub scalar field size)
            let bits: [u1; 251] = scalar.to_le_bits();
            self.scalar_mul_bits(bits)
        }
    }

    /// Scalar multiplication with bit array (little-endian)
    ///
    /// This is equivalent to ec library's bit_mul but with explicit bit input.
    /// Useful when you already have the scalar decomposed to bits.
    ///
    /// # Arguments
    /// * `bits` - Scalar in bit representation (little-endian)
    ///
    pub fn scalar_mul_bits<let N: u32>(self, bits: [u1; N]) -> Self {
        assert(self.is_on_curve(), "Point must be on curve");

        let mut result = BabyJubJubPoint::identity();

        for i in 0..N {
            result = result.double();

            if bits[N - 1 - i] == 1 {
                result = result.add(self);
            }
        }

        result
    }
    /// Base field scalar multiplication
    pub fn scalar_mul_base_field(self, scalar_fq: Field) -> Self {
        // Early termination for zero scalar
        if scalar_fq == 0 {
            BabyJubJubPoint::identity()
        } else {
            // Decompose to 254 bits
            let bits: [u1; 254] = scalar_fq.to_le_bits();

            self.scalar_mul_bits(bits)
        }
    }

    /// Validates that a field element is in the BabyJubJub scalar field Fr
    pub fn validate_babyjubjub_field(field_element: Field) {
        bn254::assert_lt(field_element, BABYJUBJUB_Fr);
    }

    pub fn validate_scalar_field_with_bits(field_element: Field) -> [u1; 251] {
        BabyJubJubPoint::validate_babyjubjub_field(field_element);
        let bits: [u1; 251] = field_element.to_le_bits();
        bits
    }

    pub fn check_sub_group(self) -> bool {
        let characteristic: [u1; 251] = [
            1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1,
            1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0,
            0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1,
        ];

        let res = esc_mul_fix_scalar(characteristic, self);
        res.is_identity()
    }

    pub fn generator_scalar_mul(scalar: Field) -> Self {
        generator_mul_fix(scalar)
    }
}
