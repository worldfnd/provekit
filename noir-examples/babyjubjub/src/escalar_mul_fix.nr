// Fixed-base scalar multiplication using windowed method
// Based on Circom's EscalarMulFix implementation
// Reference: https://github.com/iden3/circomlib/blob/master/circuits/escalarmulfix.circom

use super::BabyJubJubPoint;
use super::montogomery::MontgomeryPoint;
use super::window_table::{
    generate_window_table, generator_window_table, select_from_window_optimized,
};

pub fn segment_mul_fix<let N: u32>(
    bits: [u1; N],
    base: BabyJubJubPoint,
) -> (BabyJubJubPoint, MontgomeryPoint) {
    let mut padded_bits: [u1; 252] = [0; 252];

    for i in 0..252 {
        if i < N {
            padded_bits[i] = bits[i];
        } else {
            padded_bits[i] = 0;
        }
    }

    let base_mont = base.to_montgomery();

    let mut current_base = base_mont;

    let mut window_outputs: [MontgomeryPoint; 84] = [base_mont; 84];
    let mut bases: [MontgomeryPoint; 84] = [base_mont; 84];

    // Fixed loop: exactly 84 iterations (252 bits / 3 bits per window)
    for i in 0..84 {
        let table = generate_window_table(current_base);

        let bit0 = padded_bits[3 * i];
        let bit1 = padded_bits[3 * i + 1];
        let bit2 = padded_bits[3 * i + 2];

        let window_bits: [u1; 3] = [bit0, bit1, bit2];

        let selected = select_from_window_optimized(window_bits, table);

        window_outputs[i] = selected;
        bases[i] = current_base;

        current_base = table[7];
    }

    let mut compensation = bases[0];
    for i in 1..84 {
        compensation = compensation.add(bases[i]);
    }

    let doubled_last_base = current_base.double();
    compensation = compensation.add(doubled_last_base);

    let mut accumulator = doubled_last_base;
    for i in 0..84 {
        accumulator = accumulator.add(window_outputs[i]);
    }

    let acc_edwards = BabyJubJubPoint::from_montgomery(accumulator);
    let comp_edwards = BabyJubJubPoint::from_montgomery(compensation);

    let result = acc_edwards.subtract(comp_edwards);

    (result, current_base)
}

pub fn escalar_mul_fix(scalar: Field, base: BabyJubJubPoint) -> BabyJubJubPoint {
    if scalar == 0 {
        BabyJubJubPoint::identity()
    } else {
        let bits: [u1; 251] = scalar.to_le_bits();

        let (result, _) = segment_mul_fix(bits, base);

        result
    }
}

pub fn segment_mul_fix_generator<let N: u32>(bits: [u1; N]) -> (BabyJubJubPoint, MontgomeryPoint) {
    let generator_table = generator_window_table();

    // Calculate number of windows (each window is 3 bits)
    let num_windows = (N + 2) / 3;

    // Track current base (starts at generator, becomes 8*G, 64*G, etc.)
    let mut current_base = generator_table[0]; // 1G

    let mut window_outputs: [MontgomeryPoint; 85] = [current_base; 85];
    let mut bases: [MontgomeryPoint; 85] = [current_base; 85];
    let mut actual_windows = 0;

    // Phase 1: Process each window
    for i in 0..num_windows {
        if (3 * i) < N {
            let table = if i == 0 {
                generator_table
            } else {
                generate_window_table(current_base)
            };

            // Extract 3 bits for this window
            let bit0 = if (3 * i) < N { bits[3 * i] } else { 0 };
            let bit1 = if (3 * i + 1) < N { bits[3 * i + 1] } else { 0 };
            let bit2 = if (3 * i + 2) < N { bits[3 * i + 2] } else { 0 };

            let window_bits: [u1; 3] = [bit0, bit1, bit2];
            let selected = select_from_window_optimized(window_bits, table);

            window_outputs[i] = selected;
            bases[i] = current_base;
            actual_windows = i + 1;

            current_base = table[7];
        }
    }

    // Phase 2: Build compensation chain
    let mut compensation = bases[0];
    for i in 1..actual_windows {
        compensation = compensation.add(bases[i]);
    }

    // Phase 3: Add extra doubling for safety
    let doubled_last_base = current_base.double();
    compensation = compensation.add(doubled_last_base);

    // Phase 4: Build accumulator chain
    let mut accumulator = doubled_last_base;
    for i in 0..actual_windows {
        accumulator = accumulator.add(window_outputs[i]);
    }

    // Phase 5: Convert to Edwards and perform final compensation
    let acc_edwards = BabyJubJubPoint::from_montgomery(accumulator);
    let comp_edwards = BabyJubJubPoint::from_montgomery(compensation);
    let result = acc_edwards.subtract(comp_edwards);

    (result, current_base)
}

pub fn generator_mul_fix(scalar: Field) -> BabyJubJubPoint {
    if scalar == 0 {
        BabyJubJubPoint::identity()
    } else {
        let bits: [u1; 251] = scalar.to_le_bits();
        let (result, _) = segment_mul_fix(bits, BabyJubJubPoint::generator());
        result
    }
}

#[test]
fn test_segment_mul_fix_small() {
    let g = BabyJubJubPoint::generator();
    let bits: [u1; 3] = [1, 0, 1];

    let (result, _) = segment_mul_fix(bits, g);
    let expected = g.scalar_mul(5);

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_segment_mul_fix_medium() {
    let g = BabyJubJubPoint::generator();
    let bits: [u1; 9] = [1, 0, 1, 1, 0, 0, 0, 1, 1]; // 397 in LE

    let (result, _) = segment_mul_fix(bits, g);
    let expected = g.scalar_mul(397);

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_escalar_mul_fix_generator() {
    let g = BabyJubJubPoint::generator();

    let result_0 = escalar_mul_fix(0, g);
    assert(result_0.is_identity());

    let result_1 = escalar_mul_fix(1, g);
    assert(result_1.x == g.x);
    assert(result_1.y == g.y);

    let result_5 = escalar_mul_fix(5, g);
    let expected_5 = g.scalar_mul(5);
    assert(result_5.x == expected_5.x);
    assert(result_5.y == expected_5.y);
}

#[test]
fn test_escalar_mul_fix_large_scalar() {
    let g = BabyJubJubPoint::generator();
    let scalar = 123456789;

    let result_fixed = escalar_mul_fix(scalar, g);
    let result_basic = g.scalar_mul(scalar);

    assert(result_fixed.x == result_basic.x);
    assert(result_fixed.y == result_basic.y);
}

#[test]
fn test_generator_mul_fix() {
    // Test the convenience function
    let scalar = 999999;

    let result_fix = generator_mul_fix(scalar);
    let result_basic = BabyJubJubPoint::generator().scalar_mul(scalar);

    assert(result_fix.x == result_basic.x);
    assert(result_fix.y == result_basic.y);
}

#[test]
fn test_escalar_mul_fix_boundary() {
    let g = BabyJubJubPoint::generator();

    let large_scalar = 900719925474099;

    let result = escalar_mul_fix(large_scalar, g);
    let expected = g.scalar_mul(large_scalar);

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_optimized_generator_mul_fix() {
    let g = BabyJubJubPoint::generator();

    let scalar = 5;
    let result_optimized = generator_mul_fix(scalar);
    let result_regular = g.scalar_mul(scalar);

    assert(result_optimized.x == result_regular.x);
    assert(result_optimized.y == result_regular.y);

    let large_scalar = 123456789;
    let result_opt_large = generator_mul_fix(large_scalar);
    let result_reg_large = g.scalar_mul(large_scalar);

    assert(result_opt_large.x == result_reg_large.x);
    assert(result_opt_large.y == result_reg_large.y);

    let result_gen = generator_mul_fix(scalar);
    let result_esc = escalar_mul_fix(scalar, g);

    assert(result_gen.x == result_esc.x);
    assert(result_gen.y == result_esc.y);
}

#[test]
fn test_segment_mul_fix_generator() {
    let g = BabyJubJubPoint::generator();
    let bits: [u1; 9] = [1, 0, 1, 1, 0, 0, 0, 1, 1]; // 397 in LE

    let (result_opt, _) = segment_mul_fix_generator(bits);
    let (result_reg, _) = segment_mul_fix(bits, g);

    assert(result_opt.x == result_reg.x);
    assert(result_opt.y == result_reg.y);
}
