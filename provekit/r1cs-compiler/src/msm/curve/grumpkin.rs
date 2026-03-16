use super::Curve;

/// Grumpkin: BN254 cycle-companion curve.
/// Base field = BN254 scalar field, order = BN254 base field order.
/// Equation: y² = x³ − 17
pub struct Grumpkin;

impl Curve for Grumpkin {
    fn field_modulus_p(&self) -> [u64; 4] {
        [
            0x43e1f593f0000001,
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]
    }
    fn curve_order_n(&self) -> [u64; 4] {
        [
            0x3c208c16d87cfd47,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]
    }
    fn curve_a(&self) -> [u64; 4] {
        [0; 4]
    }
    fn curve_b(&self) -> [u64; 4] {
        [
            0x43e1f593effffff0,
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]
    }
    fn generator(&self) -> ([u64; 4], [u64; 4]) {
        ([1, 0, 0, 0], [
            0x833fc48d823f272c,
            0x2d270d45f1181294,
            0xcf135e7506a45d63,
            0x0000000000000002,
        ])
    }
    /// Offset point for accumulation blinding.
    ///
    /// NUMS (nothing-up-my-sleeve) construction:
    /// `x = SHA256("provekit-grumpkin-offset")` interpreted as big-endian
    /// integer mod p, incremented until y² = x³ + b has a square root.
    /// Canonical (smaller) y is chosen. Reproducible via
    /// `scripts/verify_offset_points.py`.
    fn offset_point(&self) -> ([u64; 4], [u64; 4]) {
        (
            [
                0x0c7f59b08d3ed494,
                0xc9c7cc25211e2d7a,
                0x39c65342a2e5e9f2,
                0x121b63f644122c3d,
            ],
            [
                0xdbecdeb7a68f782d,
                0x10f1f9045c0bc912,
                0x1cd40a11a67012e1,
                0x00767fcc149fc6b3,
            ],
        )
    }
}
