// Variable-base scalar multiplication using Montgomery arithmetic
// Based on Circom's EscalarMulAny implementation
// Reference: https://github.com/iden3/circomlib/blob/master/circuits/escalarmulany.circom

use super::BABYJUBJUB_Fr;
use super::BabyJubJubPoint;
use super::montogomery::MontgomeryPoint;

fn bit_element_mul_any(
    sel: u1,
    dbl_in: MontgomeryPoint,
    add_in: MontgomeryPoint,
) -> (MontgomeryPoint, MontgomeryPoint) {
    let dbl_out = dbl_in.double();

    let adder_result = dbl_out.add(add_in);

    let add_out = if sel == 1 { adder_result } else { add_in };

    (dbl_out, add_out)
}

pub fn segment_mul_any<let N: u32>(
    e: [u1; N],
    base: BabyJubJubPoint,
) -> (BabyJubJubPoint, MontgomeryPoint) {
    assert(N <= 248, "Segment size must be <= 248 bits");
    assert(N >= 2, "Segment size must be >= 2 bits");

    let base_mont = base.to_montgomery();

    let mut dbl_out = base_mont;
    let mut add_out = base_mont;

    for i in 1..N {
        let sel = e[i];
        let (new_dbl_out, new_add_out) = bit_element_mul_any(sel, dbl_out, add_out);
        dbl_out = new_dbl_out;
        add_out = new_add_out;
    }

    let result_edwards = BabyJubJubPoint::from_montgomery(add_out);

    let final_result = if e[0] == 1 {
        result_edwards
    } else {
        result_edwards.add(base.negate())
    };

    (final_result, dbl_out)
}

pub fn escalar_mul_any_bits<let N: u32>(bits: [u1; N], base: BabyJubJubPoint) -> BabyJubJubPoint {
    assert(N >= 2, "Must have at least 2 bits");

    let n_segments = ((N - 1) / 148) + 1;
    let last_segment_size = N - (n_segments - 1) * 148;

    let is_zero = base.is_identity();
    let g8_x = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    let g8_y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    let g8 = BabyJubJubPoint::new(g8_x, g8_y);

    let effective_base = if is_zero { g8 } else { base };

    if n_segments == 1 {
        let segment_result = process_segment_direct(bits, effective_base);
        if is_zero {
            BabyJubJubPoint::identity()
        } else {
            segment_result
        }
    } else {
        let mut first_segment_bits: [u1; 148] = [0; 148];
        for i in 0..148 {
            first_segment_bits[i] = bits[i];
        }

        let (first_result, first_dbl) =
            process_segment_with_dbl(first_segment_bits, effective_base);

        let mut accumulator = first_result;
        let mut current_dbl = first_dbl;

        for s in 1..n_segments {
            let segment_size = if s == n_segments - 1 {
                last_segment_size
            } else {
                148
            };

            let mut segment_bits: [u1; 148] = [0; 148];
            for i in 0..segment_size {
                segment_bits[i] = bits[s * 148 + i];
            }

            let doubled_dbl = current_dbl.double();

            let next_base = BabyJubJubPoint::from_montgomery(doubled_dbl);

            let (segment_result, segment_dbl) = process_segment_with_dbl(segment_bits, next_base);

            accumulator = accumulator.add(segment_result);
            current_dbl = segment_dbl;
        }

        if is_zero {
            BabyJubJubPoint::identity()
        } else {
            accumulator
        }
    }
}

fn process_segment_direct<let N: u32>(bits: [u1; N], base: BabyJubJubPoint) -> BabyJubJubPoint {
    let base_mont = base.to_montgomery();

    let mut dbl_out = base_mont;
    let mut add_out = base_mont;

    for i in 1..N {
        let sel = bits[i];
        let (new_dbl_out, new_add_out) = bit_element_mul_any(sel, dbl_out, add_out);
        dbl_out = new_dbl_out;
        add_out = new_add_out;
    }

    let result_edwards = BabyJubJubPoint::from_montgomery(add_out);

    if bits[0] == 1 {
        result_edwards
    } else {
        result_edwards.add(base.negate())
    }
}

fn process_segment_with_dbl<let N: u32>(
    bits: [u1; N],
    base: BabyJubJubPoint,
) -> (BabyJubJubPoint, MontgomeryPoint) {
    let base_mont = base.to_montgomery();

    let mut dbl_out = base_mont;
    let mut add_out = base_mont;

    for i in 1..N {
        let sel = bits[i];
        let (new_dbl_out, new_add_out) = bit_element_mul_any(sel, dbl_out, add_out);
        dbl_out = new_dbl_out;
        add_out = new_add_out;
    }

    let result_edwards = BabyJubJubPoint::from_montgomery(add_out);

    let final_result = if bits[0] == 1 {
        result_edwards
    } else {
        result_edwards.add(base.negate())
    };

    (final_result, dbl_out)
}

pub fn escalar_mul_any(scalar: Field, base: BabyJubJubPoint) -> BabyJubJubPoint {
    if scalar == 0 {
        BabyJubJubPoint::identity()
    } else {
        let bits: [u1; 251] = scalar.to_le_bits();
        escalar_mul_any_bits(bits, base)
    }
}

fn sub_if_ge(a: Field, b: Field) -> Field {
    let abits: [u1; 254] = a.to_le_bits();
    let bbits: [u1; 254] = b.to_le_bits();

    // Compute ge = (a >= b) in-circuit
    let mut gt = 0u1;
    let mut lt = 0u1;
    // walk MSB->LSB
    for i in 0..254 {
        let k = 253 - i;
        let abit = abits[k];
        let bbit = bbits[k];
        // gt |= (!lt & !gt) & (abit & !bbit)
        let a_gt_b = abit & (1 - bbit);
        let b_gt_a = bbit & (1 - abit);
        gt = gt | ((1 - lt) & (1 - gt) & a_gt_b);
        lt = lt | ((1 - lt) & (1 - gt) & b_gt_a);
    }
    let ge = 1 - lt; // a >= b iff not lt

    // mux: a - b when ge, else a
    let diff = a - b;
    a + (diff - a) * ge as Field
}

// Reduce x modulo r with at most 4 conditional subtractions.
pub fn reduce_to_fr(x: Field) -> Field {
    let mut y = x;
    y = sub_if_ge(y, BABYJUBJUB_Fr);
    y = sub_if_ge(y, BABYJUBJUB_Fr);
    y = sub_if_ge(y, BABYJUBJUB_Fr);
    y = sub_if_ge(y, BABYJUBJUB_Fr);
    y
}

fn to_251_bits(s: Field) -> [u1; 251] {
    let full: [u1; 254] = s.to_le_bits();
    let mut out: [u1; 251] = [0; 251];
    for i in 0..251 {
        out[i] = full[i];
    }
    out
}

pub fn babyjubjub_scalar_mul_base_field(e: Field, point: BabyJubJubPoint) -> BabyJubJubPoint {
    let bits: [u1; 251] = to_251_bits(e);
    let computed_result = escalar_mul_any_bits(bits, point);
    computed_result
}

#[test]
fn test_bit_element_mul_any() {
    let g = BabyJubJubPoint::generator();
    let g_mont = g.to_montgomery();

    let (dbl_out, add_out) = bit_element_mul_any(1, g_mont, g_mont);

    let expected_2g = g.double();
    let expected_2g_mont = expected_2g.to_montgomery();
    assert(dbl_out.u == expected_2g_mont.u);
    assert(dbl_out.v == expected_2g_mont.v);

    let expected_3g = g.scalar_mul(3);
    let expected_3g_mont = expected_3g.to_montgomery();
    assert(add_out.u == expected_3g_mont.u);
    assert(add_out.v == expected_3g_mont.v);
}

#[test]
fn test_segment_mul_any_small() {
    // Test with 3 bits: scalar = 5 = 0b101
    // For scalar 5, we need bits: [1, 0, 1] (MSB first, e[0]=1, e[1]=0, e[2]=1)
    let g = BabyJubJubPoint::generator();
    let bits: [u1; 3] = [1, 0, 1]; // 5 in MSB-first order

    let (result, _) = segment_mul_any(bits, g);
    let expected = g.scalar_mul(5);

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_escalar_mul_any_small() {
    let g = BabyJubJubPoint::generator();

    let result_0 = escalar_mul_any(0, g);
    assert(result_0.is_identity());

    let result_1 = escalar_mul_any(1, g);
    assert(result_1.x == g.x);
    assert(result_1.y == g.y);

    let result_5 = escalar_mul_any(5, g);
    let expected_5 = g.scalar_mul(5);
    assert(result_5.x == expected_5.x);
    assert(result_5.y == expected_5.y);
}

#[test]
fn test_escalar_mul_any_large() {
    let g = BabyJubJubPoint::generator();
    let scalar = 123456789;

    let result = escalar_mul_any(scalar, g);
    let expected = g.scalar_mul(scalar);

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_escalar_mul_any_variable_base() {
    let g = BabyJubJubPoint::generator();
    let base = g.scalar_mul(7); // Use 7*G as base
    let scalar = 13;

    let result = escalar_mul_any(scalar, base);
    let expected = base.scalar_mul(scalar); // 13 * (7*G) = 91*G

    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_escalar_mul_any_bits_direct_implementation() {
    let g = BabyJubJubPoint::generator();

    let bits_small: [u1; 10] = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
    let result_small = escalar_mul_any_bits(bits_small, g);
    let expected_small = g.scalar_mul(341);
    assert(result_small.x == expected_small.x);
    assert(result_small.y == expected_small.y);

    let large_scalar = 9007199254740991;
    let bits_large: [u1; 254] = large_scalar.to_le_bits();
    let result_large = escalar_mul_any_bits(bits_large, g);
    let expected_large = g.scalar_mul_base_field(large_scalar);
    assert(result_large.x == expected_large.x);
    assert(result_large.y == expected_large.y);
}

#[test]
fn test_escalar_mul_any_bits_zero_point() {
    let identity = BabyJubJubPoint::identity();

    let bits: [u1; 10] = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0];
    let result = escalar_mul_any_bits(bits, identity);
    assert(result.is_identity());
}
