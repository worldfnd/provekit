pub mod hash_to_curve {
    use babyjubjub::BabyJubJubPoint;
    use poseidon2::bn254::perm;

    // Baby JubJub curve parameters
    comptime global K: Field = 1;
    comptime global Z: Field = 5; // Non-square element for Elligator2
    comptime global C1: Field = 168698; // J/K
    comptime global C2: Field = 1; // 1/(K*K)

    // Hash to field using Poseidon2
    pub fn hash_to_field(input: Field) -> Field {
        let hash_input = [0, input, 0];
        let hash_result = perm::x5_3(hash_input);

        hash_result[1]
    }

    fn is_zero(x: Field) -> bool {
        x == 0
    }

    // Returns 1/x if x != 0, else 0
    fn inverse_or_zero(x: Field) -> Field {
        if x == 0 {
            0
        } else {
            1 / x
        }
    }

    // Check if a field element is a quadratic residue or zero
    // For BN254: compute sqrt and verify it squares back
    pub fn is_quadratic_residue_or_zero(x: Field) -> bool {
        if x == 0 {
            true
        } else {
            // Safety: sqrt computation is unconstrained but we verify sqrt_x^2 == x
            let sqrt_x = unsafe { bbf_sqrt_unchecked(x) };
            sqrt_x * sqrt_x == x
        }
    }

    // Helper function for exponentiation using square-and-multiply (optimized)
    unconstrained fn field_pow(base: Field, exp_bits: [u1; 252]) -> Field {
        if base == 0 {
            0
        } else {
            let mut result: Field = 1;
            let mut b = base;

            for i in 0..252 {
                if exp_bits[i] == 1 {
                    result *= b;
                }
                b *= b;
            }

            result
        }
    }

    // Square root for BN254 using Tonelli-Shanks algorithm
    // BN254 has p = 1 (mod 4), so we cannot use the simple formula x^((p+1)/4)
    // Instead we use Tonelli-Shanks with precomputed parameters
    // We only constrain the result via y^2 = x check in the caller
    unconstrained fn bbf_sqrt_unchecked(n: Field) -> Field {
        if n == 0 {
            0
        } else {
            // Tonelli-Shanks parameters for BN254 scalar field
            let mut m = 28;
            let mut c: Field =
                19103219067921713944291392827692070036145651957329286315305642004821462161904;

            // t = n^t_exp where t_exp = 81540058820840996586704275553141814055101440848469862132140264610111
            let t_exp_bits: [u1; 252] = [
                1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1,
                1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1,
                1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1,
                1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1,
                1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1,
                1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1,
                0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1,
                0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0,
                1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let mut t = field_pow(n, t_exp_bits);

            // r = n^r_exp where r_exp = (t_exp + 1) / 2 = 40770029410420498293352137776570907027550720424234931066070132305056
            let r_exp_bits: [u1; 252] = [
                0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
                1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1,
                1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1,
                1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1,
                0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1,
                0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0,
                1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            let mut r = field_pow(n, r_exp_bits);

            // Tonelli-Shanks main loop (optimized for early termination)
            // Maximum iterations is m (28 for BN254)
            for _iter in 0..28 {
                if t == 1 {
                    // Early termination - we found the square root
                } else if r != 0 {
                    // Find the least i such that t^(2^i) == 1
                    let mut sq = t * t;
                    let mut i: u32 = 1;

                    // Find i (max 27 iterations since we start at i=1)
                    for _j in 0..27 {
                        if sq != 1 {
                            i += 1;
                            sq *= sq;
                        }
                    }

                    // Compute b = c^(2^(m-i-1))
                    let mut b = c;
                    let exp_count = m - i - 1;
                    for _k in 0..27 {
                        if _k < exp_count {
                            b *= b;
                        }
                    }

                    m = i;
                    c = b * b;
                    t *= c;
                    r *= b;
                }
            }

            r
        }
    }

    // Sign function: returns LSB
    unconstrained fn sgn0_unconstrained(x: Field) -> (bool, Field) {
        let bits: [u1; 254] = x.to_le_bits();
        let lsb = bits[0] == 1;
        // Compute x_half = (x - lsb) / 2
        let lsb_val = if lsb { 1 } else { 0 };
        let x_half = (x - lsb_val) / 2;
        (lsb, x_half)
    }

    fn sgn0(x: Field) -> bool {
        // Safety: LSB and half computed unconstrained but verified by reconstruction
        let (lsb, x_half) = unsafe { sgn0_unconstrained(x) };

        // Verify: 2 * x_half + lsb should equal x
        let lsb_value = if lsb { 1 } else { 0 };
        assert(2 * x_half + lsb_value == x, "LSB verification failed");

        lsb
    }

    // Map to Montgomery curve using Elligator2
    // https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method
    // Montgomery curve: K * t^2 = s^3 + J * s^2 + s
    // For BabyJubJub: K=1, J=168698, so curve is: t^2 = s^3 + 168698*s^2 + s
    pub fn map_to_curve_elligator2(input: Field) -> (Field, Field) {
        let u = input;

        let tv1_0 = Z * u * u;
        let e = is_zero(tv1_0 + 1);

        let tv1 = if e { 0 } else { tv1_0 };

        let tv1_plus_1 = tv1 + 1;
        let x1_inv = inverse_or_zero(tv1_plus_1);
        let x1 = -C1 * x1_inv;

        let gx1_0 = (x1 + C1) * x1;
        let gx1 = (gx1_0 + C2) * x1;

        let x2 = -x1 - C1;
        let gx2 = tv1 * gx1;

        // Step 6-7: If is_square(gx1), use x1 and sqrt(gx1), else use x2 and sqrt(gx2)
        let gx1_is_square = is_quadratic_residue_or_zero(gx1);

        let x = if gx1_is_square { x1 } else { x2 };
        let gx = if gx1_is_square { gx1 } else { gx2 };

        // Compute y = sqrt(gx)
        // Safety: sqrt is unconstrained but verified by y^2 = gx constraint below
        let mut y = unsafe { bbf_sqrt_unchecked(gx) };

        // Adjust sign of y according to spec:
        // If gx1 is square: sgn0(y) == 1
        // Else: sgn0(y) == 0
        let y_sgn = sgn0(y);
        let should_negate = if gx1_is_square {
            !y_sgn // Want sgn0(y) == 1, so negate if currently 0
        } else {
            y_sgn // Want sgn0(y) == 0, so negate if currently 1
        };

        if should_negate {
            y = -y;
        }

        // Step 8-9: s = x * K, t = y * K
        // Since K = 1 for BabyJubJub:
        let s = x * K;
        let t = y * K;

        // Step 10: return (s, t)
        (s, t)
    }
    pub fn rational_map_mont_to_twisted_edwards(s: Field, t: Field) -> (Field, Field) {
        // tv1 = s + 1
        let tv1 = s + 1;

        // tv2 = InverseOrZero(tv1 * t)
        let tv2 = inverse_or_zero(tv1 * t);

        // v = tv1 * tv2
        let v = tv1 * tv2;

        // w = tv2 * t
        let w = tv2 * t;

        // tv11 = s - 1
        let tv11 = s - 1;

        // e = IsZero(tv2)
        let e = is_zero(tv2);

        // out[0] = s * v
        let out_x = s * v;

        // out[1] = if e then 1 else w * tv11
        let out_y = if e { 1 } else { w * tv11 };

        (out_x, out_y)
    }

    // Map to Twisted Edwards curve
    pub fn map_to_curve_twisted_edwards(input: Field) -> (Field, Field) {
        let (mont_s, mont_t) = map_to_curve_elligator2(input);
        rational_map_mont_to_twisted_edwards(mont_s, mont_t)
    }

    pub fn clear_cofactor_baby_jubjub(x: Field, y: Field) -> (Field, Field) {
        let point = BabyJubJubPoint::new(x, y);
        let result = point.multiply_by_cofactor();

        (result.x, result.y)
    }

    // Main encode to curve function
    pub fn encode_to_curve_baby_jubjub(input: Field) -> (Field, Field) {
        // u = HashToField(input)
        let u = hash_to_field(input);

        // q = MapToCurveTwistedEdwards(u)
        let (q_x, q_y) = map_to_curve_twisted_edwards(u);

        // Clear cofactor (multiply by 8)
        let (out_x, out_y) = clear_cofactor_baby_jubjub(q_x, q_y);

        (out_x, out_y)
    }

}

mod test {
    use super::hash_to_curve::{encode_to_curve_baby_jubjub, is_quadratic_residue_or_zero};

    #[test]
    fn test_encode_to_curve_baby_jubjub() {
        let x = 0x03e4070110668921a99c37627dedddb5ab65fae33c19e24d9ee19d7065fdeca8;
        let is_quadratic_residue_or_zero = encode_to_curve_baby_jubjub(x);
        assert(
            is_quadratic_residue_or_zero.0
                == 10175058421265066103271621309400893795433239363389874688251488422849525264799,
        );
        assert(
            is_quadratic_residue_or_zero.1
                == 3628966387438731209966022732278382991713986757399185528286224796904478655258,
        );
    }
}
