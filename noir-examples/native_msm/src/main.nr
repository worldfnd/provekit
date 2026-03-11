global GRUMPKIN_GEN_Y: Field = 17631683881184975370165255887551781615748388533673675138860;

// Hardcoded offset generators: offset = 5*G, offset_final = 2^252 * 5*G
// These are compile-time constants -- no unconstrained computation, no runtime verification needed.
global OFFSET_X: Field = 12229279139087521908560794489267966517139449915173592433539394009359081620359;
global OFFSET_Y: Field = 12096995292699515952722386974733884667125946823386040531322131902193094989869;
global OFFSET_FINAL_X: Field = 17097678145015848904467691187715743297134903912023447344174597163323183228319;
global OFFSET_FINAL_Y: Field = 14560299638432262069836824301755786319891239433999125203465365199349384123743;

// BN254 scalar field modulus as wNAF slices (MSB first).
// Used for lexicographic range check: ensures wNAF integer < p, preventing mod-p ambiguity.
global MODULUS_SLICES: [u8; 64] = [
    9, 8, 3, 2, 2, 7, 3, 9, 7, 0, 9, 8, 13, 0, 1, 4,
    13, 12, 2, 8, 2, 2, 13, 11, 4, 0, 12, 0, 10, 12, 2, 14,
    9, 4, 1, 9, 15, 4, 2, 4, 3, 12, 13, 12, 11, 8, 4, 8,
    10, 1, 15, 0, 15, 10, 12, 9, 15, 8, 0, 0, 0, 0, 0, 0,
];

struct GPoint { x: Field, y: Field }
struct GPointResult { x: Field, y: Field, is_infinity: bool }
struct Hint { lambda: Field, x3: Field, y3: Field }

// ====== Constrained EC verification ======

// ~4 constraints: verify point doubling
fn c_double(p: GPoint, h: Hint) -> GPoint {
    let xx = p.x * p.x;
    assert(h.lambda * (p.y + p.y) == 3 * xx); // a=0 for Grumpkin
    assert(h.lambda * h.lambda == h.x3 + p.x + p.x);
    assert(h.lambda * (p.x - h.x3) == h.y3 + p.y);
    GPoint { x: h.x3, y: h.y3 }
}

// ~4 constraints: verify point addition (incomplete -- offset generator prevents edge cases)
fn c_add(p1: GPoint, p2: GPoint, h: Hint) -> GPoint {
    assert(p1.x != p2.x);
    assert(h.lambda * (p2.x - p1.x) == p2.y - p1.y);
    assert(h.lambda * h.lambda == h.x3 + p1.x + p2.x);
    assert(h.lambda * (p1.x - h.x3) == h.y3 + p1.y);
    GPoint { x: h.x3, y: h.y3 }
}

// ====== Unconstrained witness generation ======

unconstrained fn u_double(p: GPoint) -> (GPoint, Hint) {
    let lambda = (3 * p.x * p.x) / (2 * p.y);
    let x3 = lambda * lambda - 2 * p.x;
    let y3 = lambda * (p.x - x3) - p.y;
    (GPoint { x: x3, y: y3 }, Hint { lambda, x3, y3 })
}

unconstrained fn u_add(p1: GPoint, p2: GPoint) -> (GPoint, Hint) {
    let lambda = (p2.y - p1.y) / (p2.x - p1.x);
    let x3 = lambda * lambda - p1.x - p2.x;
    let y3 = lambda * (p1.x - x3) - p1.y;
    (GPoint { x: x3, y: y3 }, Hint { lambda, x3, y3 })
}

// Unconstrained complete addition hint (handles add, double, and inverse cases)
unconstrained fn u_complete_add_hint(p1: GPoint, p2: GPoint) -> Hint {
    if p1.x == p2.x {
        if p1.y == p2.y {
            let (_, hint) = u_double(p1);
            hint
        } else {
            Hint { lambda: 0, x3: 0, y3: 0 }
        }
    } else {
        let (_, hint) = u_add(p1, p2);
        hint
    }
}

// Unconstrained full addition hint (handles infinity inputs)
unconstrained fn u_full_add_hint(
    p1: GPoint, p1_inf: bool,
    p2: GPoint, p2_inf: bool,
) -> Hint {
    if p1_inf | p2_inf {
        Hint { lambda: 0, x3: 0, y3: 0 }
    } else {
        u_complete_add_hint(p1, p2)
    }
}

// Constrained complete addition: handles add, double, and inverse-point cases.
// Both inputs must be valid on-curve points (not identity).
// Uses `active * constraint == 0` pattern so constraints are trivially satisfied
// when the result is the identity (inverse-point case).
fn c_complete_add(p1: GPoint, p2: GPoint, h: Hint) -> GPointResult {
    let x_eq: bool = p1.x == p2.x;
    let y_eq: bool = p1.y == p2.y;
    let is_infinity: bool = x_eq & !y_eq;
    let is_double: bool = x_eq & y_eq;
    let active: Field = (!is_infinity) as Field;

    let lambda_lhs = if is_double { p1.y + p1.y } else { p2.x - p1.x };
    let lambda_rhs = if is_double { 3 * p1.x * p1.x } else { p2.y - p1.y };
    assert(active * (h.lambda * lambda_lhs - lambda_rhs) == 0);

    // x3 verification: lambda^2 = x3 + x1 + x2 (same for add and double since x2=x1 when doubling)
    assert(active * (h.lambda * h.lambda - h.x3 - p1.x - p2.x) == 0);

    // y3 verification: lambda * (x1 - x3) = y3 + y1
    assert(active * (h.lambda * (p1.x - h.x3) - h.y3 - p1.y) == 0);

    GPointResult { x: h.x3 * active, y: h.y3 * active, is_infinity }
}

// Constrained full addition: handles all cases including identity inputs.
// This is used for the final MSM sum where either operand may be the identity.
fn c_full_add(
    p1: GPoint, p1_inf: bool,
    p2: GPoint, p2_inf: bool,
    h: Hint,
) -> GPointResult {
    let neither_inf = !p1_inf & !p2_inf;
    let both_inf = p1_inf & p2_inf;
    let only_p1_inf = p1_inf & !p2_inf;

    // EC constraints are only active when neither input is identity.
    let ec_active: Field = neither_inf as Field;

    // Determine add/double/inverse case (only meaningful when neither is identity).
    // Guard with neither_inf so garbage coordinates from identity points don't affect predicates.
    let x_eq: bool = (p1.x == p2.x) & neither_inf;
    let y_eq: bool = (p1.y == p2.y) & neither_inf;
    let is_inf_from_add: bool = x_eq & !y_eq;
    let is_double: bool = x_eq & y_eq;
    let arith_active: Field = ec_active * (!is_inf_from_add as Field);

    // Lambda, x3, y3 constraints (zeroed when inactive)
    let lambda_lhs = if is_double { p1.y + p1.y } else { p2.x - p1.x };
    let lambda_rhs = if is_double { 3 * p1.x * p1.x } else { p2.y - p1.y };
    assert(arith_active * (h.lambda * lambda_lhs - lambda_rhs) == 0);
    assert(arith_active * (h.lambda * h.lambda - h.x3 - p1.x - p2.x) == 0);
    assert(arith_active * (h.lambda * (p1.x - h.x3) - h.y3 - p1.y) == 0);

    // Output selection
    let result_is_inf: bool = both_inf | is_inf_from_add;

    let out_x = if result_is_inf { 0 }
                else if only_p1_inf { p2.x }
                else if p2_inf { p1.x }
                else { h.x3 };
    let out_y = if result_is_inf { 0 }
                else if only_p1_inf { p2.y }
                else if p2_inf { p1.y }
                else { h.y3 };

    GPointResult { x: out_x, y: out_y, is_infinity: result_is_inf }
}

unconstrained fn decompose_wnaf(scalar_lo: Field, scalar_hi: Field) -> ([u8; 64], bool) {
    let lo_bytes = scalar_lo.to_le_bytes::<16>();
    let hi_bytes = scalar_hi.to_le_bytes::<16>();
    let mut nibbles: [u8; 64] = [0; 64];
    for i in 0..16 {
        nibbles[2 * i] = lo_bytes[i] & 0x0F;
        nibbles[2 * i + 1] = lo_bytes[i] >> 4;
    }
    for i in 0..16 {
        nibbles[32 + 2 * i] = hi_bytes[i] & 0x0F;
        nibbles[32 + 2 * i + 1] = hi_bytes[i] >> 4;
    }
    let skew: bool = (nibbles[0] & 1) == 0;
    nibbles[0] = nibbles[0] + (skew as u8);
    let mut slices: [u8; 64] = [0; 64];
    slices[63] = (nibbles[0] + 15) / 2;
    for i in 1..64 {
        let nibble = nibbles[i];
        slices[63 - i] = (nibble + 15) / 2;
        if (nibble & 1) == 0 {
            slices[63 - i] += 1;
            slices[64 - i] -= 8;
        }
    }
    (slices, skew)
}

// 326 hints per scalar mul: 8 table + 1 init + 63*5 loop + 1 skew + 1 final
unconstrained fn compute_transcript(
    P: GPoint, slices: [u8; 64], skew: bool,
    offset: GPoint, offset_final: GPoint,
) -> [Hint; 326] {
    let mut h: [Hint; 326] = [Hint { lambda: 0, x3: 0, y3: 0 }; 326];
    let mut p: u32 = 0;

    // Table: 2P, then P+2P, 3P+2P, ...
    let (d2, d2h) = u_double(P);
    h[p] = d2h; p += 1;
    let mut table: [GPoint; 16] = [GPoint { x: 0, y: 0 }; 16];
    table[8] = P;
    table[7] = GPoint { x: P.x, y: 0 - P.y };
    let mut A = P;
    for i in 1..8 {
        let (s, sh) = u_add(A, d2); h[p] = sh; p += 1;
        A = s;
        table[8 + i] = A;
        table[7 - i] = GPoint { x: A.x, y: 0 - A.y };
    }

    // Init: offset + T[slices[0]]
    let (ir, ih) = u_add(offset, table[slices[0] as u32]);
    h[p] = ih; p += 1;
    let mut acc = ir;

    // 63 windows: 4 doubles + 1 add each
    for _w in 1..64 {
        for _ in 0..4 { let (d, dh) = u_double(acc); h[p] = dh; p += 1; acc = d; }
        let tp = table[slices[_w] as u32];
        let (s, sh) = u_add(acc, tp); h[p] = sh; p += 1; acc = s;
    }

    // Skew correction (always compute valid hint even if unused)
    let neg_P = GPoint { x: P.x, y: 0 - P.y };
    let (sr, sh) = u_add(acc, neg_P);
    h[p] = sh; p += 1;
    if skew { acc = sr; }

    // Final offset subtraction (complete -- handles identity result when scalar = 0)
    let neg_off = GPoint { x: offset_final.x, y: 0 - offset_final.y };
    h[p] = u_complete_add_hint(acc, neg_off);

    h
}

// ====== Scalar range check ======
// Lexicographic comparison: ensures wNAF slices represent an integer < field modulus.
// Without this, a prover could encode scalar + k*p (for k != 0) using valid 4-bit slices,
// since the Horner reconstruction only checks equality mod p.
// Mirrors noir_bigcurve's `compare_scalar_field_to_bignum`.
fn assert_slices_less_than_modulus(slices: [u8; 64]) {
    let mut found_strictly_less: bool = false;
    for i in 0..64 {
        if !found_strictly_less {
            let s = slices[i];
            let m = MODULUS_SLICES[i];
            // If we find a digit strictly less than modulus digit, scalar < modulus -- done.
            if s as u8 < m {
                found_strictly_less = true;
            } else {
                // If strictly greater at any position (without prior strictly-less), scalar >= modulus.
                assert(s == m, "wNAF scalar exceeds field modulus");
            }
        }
    }
    // If all digits equal, scalar == modulus, which is also invalid (must be strictly less).
    assert(found_strictly_less, "wNAF scalar equals field modulus");
}

// ====== Main scalar multiplication ======

fn scalar_mul_wnaf(P: GPoint, scalar_lo: Field, scalar_hi: Field) -> GPointResult {
    // 1. Decompose scalar into wNAF slices
    // Safety: slices and skew are fully constrained below (range, reconstruction, and modulus bound)
    let (slices, skew) = unsafe { decompose_wnaf(scalar_lo, scalar_hi) };

    // Range check: each slice fits in 4 bits
    for i in 0..64 { (slices[i] as Field).assert_max_bit_size::<4>(); }

    // Soundness fix #1: scalar range check -- slices represent integer < field modulus
    assert_slices_less_than_modulus(slices);

    // Reconstruction check: wNAF Horner evaluation == scalar_lo + scalar_hi * 2^128
    let mut r: Field = 0;
    for i in 0..64 { r = r * 16; r += (slices[i] as Field) * 2 - 15; }
    r -= skew as Field;

    let lo_bits: [u1; 128] = scalar_lo.to_le_bits();
    let hi_bits: [u1; 128] = scalar_hi.to_le_bits();
    let mut expected: Field = 0;
    let mut pow: Field = 1;
    for i in 0..128 { expected += (lo_bits[i] as Field) * pow; pow *= 2; }
    let two_128: Field = pow;
    let mut hi_val: Field = 0;
    pow = 1;
    for i in 0..128 { hi_val += (hi_bits[i] as Field) * pow; pow *= 2; }
    expected += hi_val * two_128;
    assert(r == expected);

    // 2. Offset generators -- hardcoded compile-time constants (soundness fix #2)
    let offset = GPoint { x: OFFSET_X, y: OFFSET_Y };
    let offset_final = GPoint { x: OFFSET_FINAL_X, y: OFFSET_FINAL_Y };

    // 3. Transcript of EC operation hints
    // Safety: every hint is verified by a constrained c_double or c_add call below
    let hints = unsafe { compute_transcript(P, slices, skew, offset, offset_final) };
    let mut hp: u32 = 0;

    // 4. Build 16-entry lookup table: T[8]=P, T[9]=3P, ..., T[15]=15P, T[7]=-P, ..., T[0]=-15P
    let d2 = c_double(P, hints[hp]); hp += 1;
    let mut tx: [Field; 16] = [0; 16];
    let mut ty: [Field; 16] = [0; 16];
    tx[8] = P.x; ty[8] = P.y;
    tx[7] = P.x; ty[7] = 0 - P.y;
    let mut A = P;
    for i in 1..8 {
        A = c_add(A, d2, hints[hp]); hp += 1;
        tx[8 + i] = A.x; ty[8 + i] = A.y;
        tx[7 - i] = A.x; ty[7 - i] = 0 - A.y;
    }

    // 5. Init accumulator: offset + T[slices[0]]
    let first = GPoint { x: tx[slices[0] as u32], y: ty[slices[0] as u32] };
    let mut acc = c_add(offset, first, hints[hp]); hp += 1;

    // 6. Main wNAF loop: 63 windows * (4 doublings + 1 table add)
    for _w in 1..64 {
        acc = c_double(acc, hints[hp]); hp += 1;
        acc = c_double(acc, hints[hp]); hp += 1;
        acc = c_double(acc, hints[hp]); hp += 1;
        acc = c_double(acc, hints[hp]); hp += 1;
        let tp = GPoint { x: tx[slices[_w] as u32], y: ty[slices[_w] as u32] };
        acc = c_add(acc, tp, hints[hp]); hp += 1;
    }

    // 7. Skew correction: if scalar was even, subtract P
    let neg_P = GPoint { x: P.x, y: 0 - P.y };
    let skew_r = c_add(acc, neg_P, hints[hp]); hp += 1;
    acc = if skew { skew_r } else { acc };

    // 8. Subtract accumulated offset: result = acc - 2^252 * offset
    // Uses complete addition to handle the identity result (scalar = 0 mod group_order)
    let neg_off = GPoint { x: offset_final.x, y: 0 - offset_final.y };
    c_complete_add(acc, neg_off, hints[hp])
}

/// 2-point MSM on Grumpkin: s1*G + s2*G
fn main(
    scalar1_lo: pub Field, scalar1_hi: pub Field,
    scalar2_lo: pub Field, scalar2_hi: pub Field,
) -> pub (Field, Field, bool) {
    let g = GPoint { x: 1, y: GRUMPKIN_GEN_Y };

    let r1 = scalar_mul_wnaf(g, scalar1_lo, scalar1_hi);
    let r2 = scalar_mul_wnaf(g, scalar2_lo, scalar2_hi);

    // Full addition: handles r1 == r2 (doubling), r1 == -r2 (identity), and identity inputs
    let add_hint = unsafe {
        u_full_add_hint(
            GPoint { x: r1.x, y: r1.y }, r1.is_infinity,
            GPoint { x: r2.x, y: r2.y }, r2.is_infinity,
        )
    };
    let result = c_full_add(
        GPoint { x: r1.x, y: r1.y }, r1.is_infinity,
        GPoint { x: r2.x, y: r2.y }, r2.is_infinity,
        add_hint,
    );

    // Verify result is on Grumpkin (skip for identity)
    let on_curve = result.y * result.y - (result.x * result.x * result.x - 17);
    assert((!result.is_infinity as Field) * on_curve == 0);

    (result.x, result.y, result.is_infinity)
}
