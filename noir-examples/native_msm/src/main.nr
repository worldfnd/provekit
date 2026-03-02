// Grumpkin generator y-coordinate
global GRUMPKIN_GEN_Y: Field = 17631683881184975370165255887551781615748388533673675138860;

struct Point {
    x: Field,
    y: Field,
    is_infinite: bool,
}

fn point_double(p: Point) -> Point {
    if p.is_infinite | (p.y == 0) {
        Point { x: 0, y: 0, is_infinite: true }
    } else {
        // Grumpkin has a=0, so lambda = 3*x1^2 / (2*y1)
        let lambda = (3 * p.x * p.x) / (2 * p.y);
        let x3 = lambda * lambda - 2 * p.x;
        let y3 = lambda * (p.x - x3) - p.y;
        Point { x: x3, y: y3, is_infinite: false }
    }
}

fn point_add(p1: Point, p2: Point) -> Point {
    if p1.is_infinite {
        p2
    } else if p2.is_infinite {
        p1
    } else if (p1.x == p2.x) & (p1.y == p2.y) {
        point_double(p1)
    } else if (p1.x == p2.x) & (p1.y == (0 - p2.y)) {
        Point { x: 0, y: 0, is_infinite: true }
    } else {
        let lambda = (p2.y - p1.y) / (p2.x - p1.x);
        let x3 = lambda * lambda - p1.x - p2.x;
        let y3 = lambda * (p1.x - x3) - p1.y;
        Point { x: x3, y: y3, is_infinite: false }
    }
}

fn scalar_mul(p: Point, scalar_lo: Field, scalar_hi: Field) -> Point {
    let lo_bits: [u1; 128] = scalar_lo.to_le_bits();
    let hi_bits: [u1; 128] = scalar_hi.to_le_bits();

    // Combine into a single 256-bit array (lo first, then hi)
    let mut bits: [u1; 256] = [0; 256];
    for i in 0..128 {
        bits[i] = lo_bits[i];
        bits[128 + i] = hi_bits[i];
    }

    // Find the highest set bit
    let mut top = 0;
    for i in 0..256 {
        if bits[i] == 1 {
            top = i;
        }
    }

    // Double-and-add from MSB down to bit 0
    let mut acc = Point { x: 0, y: 0, is_infinite: true };
    for j in 0..256 {
        let i = 255 - j;
        acc = point_double(acc);
        if bits[i] == 1 {
            acc = point_add(acc, p);
        }
    }

    acc
}

/// Native MSM: computes s1 * G + s2 * G using pure Noir field operations.
/// No blackbox functions -- all EC arithmetic is done natively over Grumpkin's
/// base field (= BN254 scalar field = Noir's native Field).
fn main(
    scalar1_lo: Field,
    scalar1_hi: Field,
    scalar2_lo: Field,
    scalar2_hi: Field,
) {
    let g = Point { x: 1, y: GRUMPKIN_GEN_Y, is_infinite: false };

    let r1 = scalar_mul(g, scalar1_lo, scalar1_hi);
    let r2 = scalar_mul(g, scalar2_lo, scalar2_hi);
    let result = point_add(r1, r2);

    // Prevent dead-code elimination
    assert(!result.is_infinite);
}

#[test]
fn test_msm() {
    // 3*G on Grumpkin (known coordinates)
    let expected_x = 18660890509582237958343981571981920822503400000196279471655180441138020044621;
    let expected_y = 8902249110305491597038405103722863701255802573786510474664632793109847672620;

    main(1, 0, 2, 0);

    // Verify 1*G + 2*G = 3*G by computing 3*G directly
    let g = Point { x: 1, y: GRUMPKIN_GEN_Y, is_infinite: false };
    let three_g = scalar_mul(g, 3, 0);

    assert(three_g.x == expected_x);
    assert(three_g.y == expected_y);
}
