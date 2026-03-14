use super::Curve;

/// SECP256R1 (NIST P-256).
/// Equation: y² = x³ + ax + b
pub struct Secp256r1;

impl Curve for Secp256r1 {
    fn field_modulus_p(&self) -> [u64; 4] {
        [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001]
    }
    fn curve_order_n(&self) -> [u64; 4] {
        [
            0xf3b9cac2fc632551,
            0xbce6faada7179e84,
            0xffffffffffffffff,
            0xffffffff00000000,
        ]
    }
    fn curve_a(&self) -> [u64; 4] {
        [
            0xfffffffffffffffc,
            0x00000000ffffffff,
            0x0000000000000000,
            0xffffffff00000001,
        ]
    }
    fn curve_b(&self) -> [u64; 4] {
        [
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]
    }
    fn generator(&self) -> ([u64; 4], [u64; 4]) {
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
    fn offset_point(&self) -> ([u64; 4], [u64; 4]) {
        (
            [
                0x57c84fc9d789bd85,
                0xfc35ff7dc297eac3,
                0xfb982fd588c6766e,
                0x447d739beedb5e67,
            ],
            [
                0x0c7e33c972e25b32,
                0x3d349b95a7fae500,
                0xe12e9d953a4aaff7,
                0x2d4825ab834131ee,
            ],
        )
    }
}
