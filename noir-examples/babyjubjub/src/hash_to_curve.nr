// Hash to Curve for BabyJubJub
// Implements the Elligator2 method from RFC 9380
// https://www.rfc-editor.org/rfc/rfc9380.html

use super::BabyJubJubPoint;
use poseidon2::bn254::perm;

comptime global Z: Field = 5;
global C1: u32 = 28;
global C3: Field = 40770029410420498293352137776570907027550720424234931066070132305055;
global C5: Field = 19103219067921713944291392827692070036145651957329286315305642004821462161904;

fn hash_to_field(input: Field) -> Field {
    // element 0 is the DS string "OPRF_HashToField_BabyJubJub"
    let hash_input = [32627786498498119128812045057993354633158048678109587794777765218, input, 0];
    let hash_result = perm::x5_3(hash_input);

    hash_result[1]
}

fn is_zero(x: Field) -> bool {
    x == 0
}

unconstrained fn inverse_or_zero_unconstrained(x: Field) -> Field {
    if x == 0 {
        0
    } else {
        1 / x
    }
}

fn inverse_or_zero(x: Field) -> Field {
    // SAFETY: We constrain the inverse below
    let inv = unsafe { inverse_or_zero_unconstrained(x) };
    let is_zero = 1 - x * inv;
    // Constraint strategy:
    // if x != 0
    //  then is_zero must be 0 due to constraint 1 => x * inv = 1, therefore inv is the inverse of x
    // if x == 0
    //  then is_zero must be 1 due to the definition above, since x = 0. inv could be anything, but we enforce inv = 0 in constraints 2 below

    // These are the two constraints enforcing above logic:
    // One of x or is_zero must be zero
    assert(x * is_zero == 0, "InverseOrZero zero constraint 1 failed");
    // One of inv or is_zero must be zero
    assert(inv * is_zero == 0, "InverseOrZero zero constraint 2 failed");
    inv
}

fn pow(x: Field, y: Field) -> Field {
    let mut r = 1 as Field;
    let b: [u1; 254] = y.to_le_bits();

    for i in 0..254 {
        r *= r;
        r *= (b[254 - 1 - i] as Field) * x + (1 - b[254 - 1 - i] as Field);
    }

    r
}

unconstrained fn legendre(x: Field) -> Field {
    if x == 0 {
        0
    } else {
        pow(x, (0 - 1) / 2)
    }
}

unconstrained fn sqrt(x: Field) -> Field {
    let mut z = pow(x, C3);
    let mut t = z * z * x;
    z *= x;
    let mut b = t;
    let mut c = C5;

    for i in 0..(C1 - 1) {
        for _j in 1..(C1 - i - 1) {
            b *= b;
        }

        z *= if b == 1 { 1 } else { c };

        c *= c;

        t *= if b == 1 { 1 } else { c };

        b = t;
    }

    z
}

// Check if a field element is a quadratic residue or zero
fn is_quadratic_residue_or_zero(x: Field) -> bool {
    // SAFETY:
    // Constraint strategy, from (<https://eprint.iacr.org/2021/984.pdf>, page 4):
    // Let l = Legendre(a) in { -1, 0, 1 }.
    // Introduce a witness b intended to be a square root:
    // Enforce: l(l-1)(b^2 - n*a) + (l+1)(b^2 - a) == 0
    // For l =  1: (l(l-1)) = 0 and (l+1) = 2 => b^2 = a
    // For l = -1: (l(l-1)) = 2 and (l+1) = 0 => b^2 = n*a
    // For l =  0: (l(l-1)) = 0 and (l+1) = 1 => b^2 = a (which forces a to be 0 or a quadratic residue)
    // Note that the above checks from the paper would also allow for a=0,b=0, but l=-1.
    // Therefore we add another constraint enforcing a=0 => l=0, see below.
    let l = unsafe { legendre(x) };
    assert(l * (l - 1) * (l + 1) == 0, "l must be in {-1,0,1}"); // l in {-1,0,1}

    // n is the smallest non-quadratic residue in BN254
    let n = 5;
    let na = n * x;
    let sqrt_in = if (l == -1) { na } else { x };
    // SAFETY: We constrain b to be the square root of either na or a, depending on the value of l.
    let b = unsafe { sqrt(sqrt_in) };

    let s_na = l * (l - 1); // 0 when l in {0,1}, 2 when l = -1
    let s_a = l + 1; // 0 when l = -1, 1 when l = 0, 2 when l = 1

    let b2 = b * b;
    let c_na = b2 - na;
    let c_a = b2 - x;
    assert(s_na * c_na + s_a * c_a == 0, "b must be a square root of na or a");

    // Constraint a=0 => l=0
    // at least one of l and (isZero(a)) need to be 0
    // This disallows the case of l!=0 and a==0, the case l==0 and a==0 is as expected, same with l!=0 and a!=0.
    // There is still the case of l==0 and a!=0 which would be allowed by this and would give an invalid legendre symbol for a.
    // However we enforce in that case (l = 0) that a = b^2, which still produces the correct high-level output for this gadget, since l in {0,1} and we do not directly return l.
    assert((x == 0) as Field * l == 0);
    l != -1
}

fn sgn0(x: Field) -> bool {
    x.sgn0() == 1
}

// Map to Montgomery curve using Elligator2
// https://www.rfc-editor.org/rfc/rfc9380.html#name-elligator-2-method
// Montgomery curve: K * t^2 = s^3 + J * s^2 + s
// For BabyJubJub: K=1, J=168698, so curve is: t^2 = s^3 + 168698*s^2 + s
pub fn map_to_curve_elligator2(input: Field) -> (Field, Field) {
    let k = 1;
    let c1 = 168698;
    let c2 = 1;

    let u = input;

    let tv1_0 = Z * u * u;
    let e = is_zero(tv1_0 + 1);

    let tv1 = if e { 0 } else { tv1_0 };

    let tv1_plus_1 = tv1 + 1;
    let x1_inv = inverse_or_zero(tv1_plus_1);
    let x1 = -c1 * x1_inv;

    let gx1_0 = (x1 + c1) * x1;
    let gx1 = (gx1_0 + c2) * x1;

    let x2 = -x1 - c1;
    let gx2 = tv1 * gx1;

    // Step 6-7: If is_square(gx1), use x1 and sqrt(gx1), else use x2 and sqrt(gx2)
    let gx1_is_square = is_quadratic_residue_or_zero(gx1);

    let x = if gx1_is_square { x1 } else { x2 };
    let gx = if gx1_is_square { gx1 } else { gx2 };

    // Compute y = sqrt(gx)
    // Safety: sqrt is unconstrained but verified by y^2 = gx constraint below
    let mut y = unsafe { sqrt(gx) };
    assert(y * y == gx, "y must be a square root of gx");

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

    // Step 8-9: s = x * K, k = y * k
    let s = x * k;
    let t = y * k;

    // Step 10: return (s, t)
    (s, t)
}

fn rational_map_mont_to_twisted_edwards(s: Field, t: Field) -> (Field, Field) {
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
fn map_to_curve_twisted_edwards(input: Field) -> (Field, Field) {
    let (mont_s, mont_t) = map_to_curve_elligator2(input);
    rational_map_mont_to_twisted_edwards(mont_s, mont_t)
}

fn clear_cofactor_baby_jubjub(x: Field, y: Field) -> (Field, Field) {
    let point = BabyJubJubPoint::new(x, y);
    let result = point.multiply_by_cofactor();

    (result.x, result.y)
}

// Main encode to curve function
pub fn encode(input: Field) -> (Field, Field) {
    // u = HashToField(input)
    let u = hash_to_field(input);

    // q = MapToCurveTwistedEdwards(u)
    let (q_x, q_y) = map_to_curve_twisted_edwards(u);

    // Clear cofactor (multiply by 8)
    let (out_x, out_y) = clear_cofactor_baby_jubjub(q_x, q_y);

    (out_x, out_y)
}

#[test]
fn test_encode_to_curve_kat0() {
    let input = 0x03e4070110668921a99c37627dedddb5ab65fae33c19e24d9ee19d7065fdeca8;
    let (x, y) = encode(input);

    assert(
        x == 10317659717708787122683977912952208883341451354299498236440964928299898571531,
        "encode x mismatch for test vector",
    );
    assert(
        y == 2771878628977713302835201233169750856073682825638128695522023521672351725258,
        "encode y mismatch for test vector",
    );
}

#[test]
fn test_encode_to_curve_kat1() {
    let input = 0x42;
    let (x, y) = encode(input);
    assert(
        x == 16453178030699411958341692808730701741568100876455568813278163225032347056514,
        "encode x mismatch for test vector",
    );
    assert(
        y == 5447922750205248208490261749483809853022174346498064122782172531486866662376,
        "encode y mismatch for test vector",
    );
}

#[test]
fn test_encode_to_curve_kat2() {
    let input = 0;
    let (x, y) = encode(input);
    assert(
        x == 16605852874433019712683889710166313607515083375138125349412270828059484170936,
        "encode x mismatch for test vector",
    );
    assert(
        y == 12075050546928691602283582412953179086742727007172364313655633055645374686589,
        "encode y mismatch for test vector",
    );
}
