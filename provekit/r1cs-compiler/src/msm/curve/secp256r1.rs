use super::{Curve, U256};

/// SECP256R1 (NIST P-256).
/// Equation: y² = x³ + ax + b
pub struct Secp256r1;

impl Curve for Secp256r1 {
    fn field_modulus_p(&self) -> U256 {
        [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001]
    }
    fn curve_order_n(&self) -> U256 {
        [
            0xf3b9cac2fc632551,
            0xbce6faada7179e84,
            0xffffffffffffffff,
            0xffffffff00000000,
        ]
    }
    fn curve_a(&self) -> U256 {
        [
            0xfffffffffffffffc,
            0x00000000ffffffff,
            0x0000000000000000,
            0xffffffff00000001,
        ]
    }
    fn curve_b(&self) -> U256 {
        [
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]
    }
    fn generator(&self) -> (U256, U256) {
        (
            [
                0xf4a13945d898c296,
                0x77037d812deb33a0,
                0xf8bce6e563a440f2,
                0x6b17d1f2e12c4247,
            ],
            [
                0xcbb6406837bf51f5,
                0x2bce33576b315ece,
                0x8ee7eb4a7c0f9e16,
                0x4fe342e2fe1a7f9b,
            ],
        )
    }
    /// Offset point for accumulation blinding.
    ///
    /// NUMS (nothing-up-my-sleeve) construction:
    /// `x = SHA256("provekit-secp256r1-offset")` interpreted as big-endian
    /// integer mod p, incremented until y² = x³ + ax + b has a square root.
    /// Canonical (smaller) y is chosen. Reproducible via
    /// `scripts/verify_offset_points.py`.
    fn offset_point(&self) -> (U256, U256) {
        (
            [
                0x3b8d6e63154ac0b8,
                0x9d50c8f4c290feb5,
                0x27080c391ced0ac0,
                0x24d812942f1c942a,
            ],
            [
                0x1d028e001bc65cb8,
                0xc4cb905df8bd1f90,
                0x9f519d447e4a2d9d,
                0x7c9e0b6ce248a7a0,
            ],
        )
    }
}
