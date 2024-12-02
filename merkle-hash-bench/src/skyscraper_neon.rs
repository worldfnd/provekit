use std::arch::aarch64::*;

/// Four Bn254 field elements.
pub type El4 = (uint32x4x4_t, uint32x4x4_t);

/// Multiply two vectors of 4 32-bit integers to produce two vectors of 2 64-bit integers.
pub unsafe fn mul(a: uint32x4_t, b: uint32x4_t) -> uint64x2x2_t {
    uint64x2x2_t(
        vmull_u32(vget_low_u32(a), vget_low_u32(b)),
        vmull_high_u32(a, b),
    )
}

/// 4-wide add with carry
pub unsafe fn adc_start(a: uint32x4_t, b: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
    let sum = vaddq_u32(a, b);

    /// This sets `carry` to 0 if no carry or -1 if there was a carry.
    let carry = vcltq_u32(sum, a);
    (sum, carry)
}

/// Carry chain
pub unsafe fn adc_chain(a: uint32x4_t, b: uint32x4_t, c: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
    let sum = vaddq_u32(a, b);
    let carry1 = vcltq_u32(sum, a);
    let sum2 = vsubq_u32(sum, c);
    let carry2 = vcltq_u32(sum2, sum);
    let carry = vorrq_u32(carry1, carry2);
    (sum2, carry)
}

/// Carry chain
pub unsafe fn adc_final(a: uint32x4_t, b: uint32x4_t, c: uint32x4_t) -> uint32x4_t {
    let sum = vaddq_u32(a, b);
    let sum2 = vsubq_u32(sum, c);
    sum2
}

pub unsafe fn add(a: El4, b: El4) -> El4 {
    let (n0, carry) = adc_start(a.0 .0, b.0 .0);
    let (n1, carry) = adc_chain(a.0 .1, b.0 .1, carry);
    let (n2, carry) = adc_chain(a.0 .2, b.0 .2, carry);
    let (n3, carry) = adc_chain(a.0 .3, b.0 .3, carry);
    let (n4, carry) = adc_chain(a.1 .0, b.1 .0, carry);
    let (n5, carry) = adc_chain(a.1 .1, b.1 .1, carry);
    let (n6, carry) = adc_chain(a.1 .2, b.1 .2, carry);
    let n7 = adc_final(a.1 .3, b.1 .3, carry);
    (uint32x4x4_t(n0, n1, n2, n3), uint32x4x4_t(n4, n5, n6, n7))
}
