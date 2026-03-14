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
    fn offset_point(&self) -> ([u64; 4], [u64; 4]) {
        (
            [
                0x626578b496650e95,
                0x8678dcf264df6c01,
                0xf0b3eb7e6d02aba8,
                0x223748a4c4edde75,
            ],
            [
                0xb75fb4c26bcd4f35,
                0x4d4ba4d97d5f99d9,
                0xccab35fdbf52368a,
                0x25b41c5f56f8472b,
            ],
        )
    }
}
