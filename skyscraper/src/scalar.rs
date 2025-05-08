use {
    crate::constants::{MODULUS, ROUND_CONSTANTS},
    block_multiplier::{block_sqr, scalar_sqr},
    fp_rounding::{RoundingGuard, Zero},
    seq_macro::seq,
};

seq!(I in 0..18 {
    pub const MODULUS_1_MINUS_RC: [[u64; 4]; 18] = [
        #(const_minus(MODULUS[1], ROUND_CONSTANTS[I]),)*
    ];
});
seq!(I in 0..18 {
    pub const MODULUS_2_MINUS_RC: [[u64; 4]; 18] = [
        #(const_minus(MODULUS[2], ROUND_CONSTANTS[I]),)*
    ];
});
seq!(I in 0..18 {
    pub const MODULUS_3_MINUS_RC: [[u64; 4]; 18] = [
        #(const_minus(MODULUS[3], ROUND_CONSTANTS[I]),)*
    ];
});
seq!(I in 0..18 {
    pub const MODULUS_4_MINUS_RC: [[u64; 4]; 18] = [
        #(const_minus(MODULUS[4], ROUND_CONSTANTS[I]),)*
    ];
});
seq!(I in 0..18 {
    pub const MODULUS_5_MINUS_RC: [[u64; 4]; 18] = [
        #(const_minus(MODULUS[5], ROUND_CONSTANTS[I]),)*
    ];
});

pub const fn const_minus(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (r0, borrow) = l[0].overflowing_sub(r[0]);
    let (r1, borrow) = l[1].borrowing_sub(r[1], borrow);
    let (r2, borrow) = l[2].borrowing_sub(r[2], borrow);
    let (r3, borrow) = l[3].borrowing_sub(r[3], borrow);
    assert!(!borrow);
    [r0, r1, r2, r3]
}

#[inline]
pub fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (l, r) = (reduce_4p(l), reduce_4p(r));
    debug_assert!(less_than(l, MODULUS[1]));
    debug_assert!(less_than(r, MODULUS[1]));
    // TODO: Re-do the range analysis.
    let a = l;
    let (l, r) = (wrapping_add(r, scalar_sqr(l)), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 1), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 2), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 3), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 4), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 5), l);
    let (l, r) = (x2p_plus_bar0p_plus_rc_eq0p(r, bar_u8(l), 6), l);
    let (l, r) = (x0p_plus_bar0p_plus_rc_eq0p(r, bar_u8(l), 7), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 8), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 9), l);
    let (l, r) = (x0p_plus_bar0p_plus_rc_eq0p(r, bar_u8(l), 10), l);
    let (l, r) = (x0p_plus_bar0p_plus_rc_eq0p(r, bar_u8(l), 11), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 12), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 13), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 14), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 15), l);
    let (l, r) = (x0p_plus_sqr3p_plus_rc_eq0p(r, scalar_sqr(l), 16), l);
    x0p_plus_sqr1p_plus_y0p_eq0p(r, scalar_sqr(l), a)
}

#[inline]
pub fn block_compress(
    _rtz: &RoundingGuard<Zero>,
    l_0: [u64; 4],
    l_1: [u64; 4],
    l_2: [u64; 4],
    r_0: [u64; 4],
    r_1: [u64; 4],
    r_2: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    let a_0 = l_0;
    let a_1 = l_1;
    let a_2 = l_2;
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let (l_0, r_0) = (wrapping_add(r_0, sqr_0), l_0);
    let (l_1, r_1) = (wrapping_add(r_1, sqr_1), l_1);
    let (l_2, r_2) = (wrapping_add(r_2, sqr_2), l_2);
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let (l_0, r_0) = (x0p_plus_sqr3p_plus_rc_eq0p(r_0, sqr_0, 0), l_0);
    let (l_1, r_1) = (x0p_plus_sqr3p_plus_rc_eq0p(r_1, sqr_1, 0), l_1);
    let (l_2, r_2) = (x0p_plus_sqr3p_plus_rc_eq0p(r_2, sqr_2, 0), l_2);
    let bar_0 = bar_u8(l_0);
    let bar_1 = bar_u8(l_1);
    let bar_2 = bar_u8(l_2);
    let (l_0, r_0) = (x2p_plus_bar0p_plus_rc_eq0p(r_0, bar_0, 1), l_0);
    let (l_1, r_1) = (x2p_plus_bar0p_plus_rc_eq0p(r_1, bar_1, 1), l_1);
    let (l_2, r_2) = (x2p_plus_bar0p_plus_rc_eq0p(r_2, bar_2, 1), l_2);
    let bar_0 = bar_u8(l_0);
    let bar_1 = bar_u8(l_1);
    let bar_2 = bar_u8(l_2);
    let (l_0, r_0) = (x0p_plus_bar0p_plus_rc_eq0p(r_0, bar_0, 2), l_0);
    let (l_1, r_1) = (x0p_plus_bar0p_plus_rc_eq0p(r_1, bar_1, 2), l_1);
    let (l_2, r_2) = (x0p_plus_bar0p_plus_rc_eq0p(r_2, bar_2, 2), l_2);
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let (l_0, r_0) = (x0p_plus_sqr2p_plus_rc_eq0p(r_0, sqr_0, 3), l_0);
    let (l_1, r_1) = (x0p_plus_sqr2p_plus_rc_eq0p(r_1, sqr_1, 3), l_1);
    let (l_2, r_2) = (x0p_plus_sqr2p_plus_rc_eq0p(r_2, sqr_2, 3), l_2);
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let (l_0, r_0) = (x0p_plus_sqr1p_plus_rc_eq0p(r_0, sqr_0, 4), l_0);
    let (l_1, r_1) = (x0p_plus_sqr1p_plus_rc_eq0p(r_1, sqr_1, 4), l_1);
    let (l_2, r_2) = (x0p_plus_sqr1p_plus_rc_eq0p(r_2, sqr_2, 4), l_2);
    let bar_0 = bar_u8(l_0);
    let bar_1 = bar_u8(l_1);
    let bar_2 = bar_u8(l_2);
    let (l_0, r_0) = (x0p_plus_bar0p_plus_rc_eq0p(r_0, bar_0, 5), l_0);
    let (l_1, r_1) = (x0p_plus_bar0p_plus_rc_eq0p(r_1, bar_1, 5), l_1);
    let (l_2, r_2) = (x0p_plus_bar0p_plus_rc_eq0p(r_2, bar_2, 5), l_2);
    let bar_0 = bar_u8(l_0);
    let bar_1 = bar_u8(l_1);
    let bar_2 = bar_u8(l_2);
    let (l_0, r_0) = (x0p_plus_bar0p_plus_rc_eq0p(r_0, bar_0, 6), l_0);
    let (l_1, r_1) = (x0p_plus_bar0p_plus_rc_eq0p(r_1, bar_1, 6), l_1);
    let (l_2, r_2) = (x0p_plus_bar0p_plus_rc_eq0p(r_2, bar_2, 6), l_2);
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let (l_0, r_0) = (x0p_plus_sqr1p_plus_rc_eq0p(r_0, sqr_0, 7), l_0);
    let (l_1, r_1) = (x0p_plus_sqr1p_plus_rc_eq0p(r_1, sqr_1, 7), l_1);
    let (l_2, r_2) = (x0p_plus_sqr1p_plus_rc_eq0p(r_2, sqr_2, 7), l_2);
    let (sqr_0, sqr_1, sqr_2) = block_sqr(_rtz, l_0, l_1, l_2);
    let l_0 = x0p_plus_sqr1p_plus_y0p_eq0p(r_0, sqr_0, a_0);
    let l_1 = x0p_plus_sqr1p_plus_y0p_eq0p(r_1, sqr_1, a_1);
    let l_2 = x0p_plus_sqr1p_plus_y0p_eq0p(r_2, sqr_2, a_2);
    (l_0, l_1, l_2)
}

#[inline(always)]
fn wrapping_add(x: [u64; 4], y: [u64; 4]) -> [u64; 4] {
    let x_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(x) };
    let y_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(y) };
    let (lo, c) = x_u128[0].overflowing_add(y_u128[0]);
    let (hi, _) = x_u128[1].carrying_add(y_u128[1], c);
    unsafe { std::mem::transmute::<[u128; 2], [u64; 4]>([lo, hi]) }
}

#[inline(always)]
fn wrapping_sub(x: [u64; 4], y: [u64; 4]) -> [u64; 4] {
    let x_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(x) };
    let y_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(y) };
    let (lo, b) = x_u128[0].overflowing_sub(y_u128[0]);
    let (hi, _) = x_u128[1].borrowing_sub(y_u128[1], b);
    unsafe { std::mem::transmute::<[u128; 2], [u64; 4]>([lo, hi]) }
}

#[inline(always)]
fn overflowing_sub(x: [u64; 4], y: [u64; 4]) -> ([u64; 4], bool) {
    let x_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(x) };
    let y_u128 = unsafe { std::mem::transmute::<[u64; 4], [u128; 2]>(y) };
    let (lo, b) = x_u128[0].overflowing_sub(y_u128[0]);
    let (hi, b) = x_u128[1].borrowing_sub(y_u128[1], b);
    (
        unsafe { std::mem::transmute::<[u128; 2], [u64; 4]>([lo, hi]) },
        b,
    )
}

#[inline(always)]
fn reduce_1p(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[2]));
    let (xr, c) = overflowing_sub(x, MODULUS[1]);
    if c {
        x
    } else {
        xr
    }
}

#[inline(always)]
fn reduce_2p(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[3]));
    let msb0 = (x[3] >> 63) != 0;
    let msb1 = ((x[3] << 1) >> 63) != 0;
    if msb0 {
        wrapping_sub(x, MODULUS[2])
    } else if msb1 {
        reduce_1p(wrapping_sub(x, MODULUS[1]))
    } else {
        reduce_1p(x)
    }
}

#[inline(always)]
fn reduce_3p(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[4]));
    let msb0 = (x[3] >> 63) != 0;
    let msb1 = ((x[3] << 1) >> 63) != 0;
    if msb0 {
        reduce_1p(wrapping_sub(x, MODULUS[2]))
    } else if msb1 {
        reduce_1p(wrapping_sub(x, MODULUS[1]))
    } else {
        reduce_1p(x)
    }
}

#[inline(always)]
fn reduce_4p(x: [u64; 4]) -> [u64; 4] {
    let msb = (x[3] >> 62) as u8;
    if msb == 0 {
        reduce_1p(x)
    } else {
        let r = if msb == 1 {
            MODULUS[1]
        } else if msb == 2 {
            MODULUS[2]
        } else {
            MODULUS[3]
        };
        reduce_1p(wrapping_sub(x, r))
    }
}

#[inline(always)]
fn bar_u8(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[1]));
    let mut x_u8 = unsafe { std::mem::transmute::<[u64; 4], [u8; 32]>(x) };
    for i in 0..32 {
        let v = x_u8[i];
        x_u8[i] = (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1);
    }
    let x = unsafe { std::mem::transmute::<[u8; 32], [u64; 4]>(x_u8) };
    [x[2], x[3], x[0], x[1]]
}

#[inline(always)]
fn x0p_plus_sqr3p_plus_rc_eq0p(x: [u64; 4], sqr: [u64; 4], rc_idx: usize) -> [u64; 4] {
    debug_assert!(less_than(sqr, MODULUS[3]));
    let x_plus_sqr = wrapping_add(x, sqr);
    let (tmp, b) = overflowing_sub(x_plus_sqr, MODULUS_1_MINUS_RC[rc_idx]);
    if b {
        wrapping_add(x_plus_sqr, ROUND_CONSTANTS[rc_idx])
    } else {
        reduce_4p(tmp)
    }
}

#[inline(always)]
fn x2p_plus_bar0p_plus_rc_eq0p(x: [u64; 4], bar: [u64; 4], rc_idx: usize) -> [u64; 4] {
    let msb0 = (bar[3] >> 62) as u8;
    let msb1 = ((bar[3] << 2) >> 63) != 0;
    let bar_plus_rc;
    if msb0 == 0 {
        bar_plus_rc = wrapping_add(bar, ROUND_CONSTANTS[rc_idx]);
    } else if msb0 == 1 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_1_MINUS_RC[rc_idx]);
    } else if msb0 == 2 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_2_MINUS_RC[rc_idx]);
    } else if !msb1 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_3_MINUS_RC[rc_idx]);
    } else {
        bar_plus_rc = wrapping_sub(bar, MODULUS_4_MINUS_RC[rc_idx]);
    }
    let tmp = wrapping_add(bar_plus_rc, x);
    reduce_4p(tmp)
}

#[inline(always)]
fn x0p_plus_bar0p_plus_rc_eq0p(x: [u64; 4], bar: [u64; 4], rc_idx: usize) -> [u64; 4] {
    let msb0 = (bar[3] >> 62) as u8;
    let msb1 = ((bar[3] << 2) >> 63) != 0;
    let bar_plus_rc;
    if msb0 == 0 {
        bar_plus_rc = wrapping_add(bar, ROUND_CONSTANTS[rc_idx]);
    } else if msb0 == 1 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_1_MINUS_RC[rc_idx]);
    } else if msb0 == 2 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_2_MINUS_RC[rc_idx]);
    } else if !msb1 {
        bar_plus_rc = wrapping_sub(bar, MODULUS_3_MINUS_RC[rc_idx]);
    } else {
        bar_plus_rc = wrapping_sub(bar, MODULUS_4_MINUS_RC[rc_idx]);
    }
    let tmp = wrapping_add(bar_plus_rc, x);
    reduce_3p(tmp)
}

#[inline(always)]
fn x0p_plus_sqr2p_plus_rc_eq0p(x: [u64; 4], sqr: [u64; 4], rc_idx: usize) -> [u64; 4] {
    let x_plus_sqr = wrapping_add(x, sqr);
    let (tmp, b) = overflowing_sub(x_plus_sqr, MODULUS_1_MINUS_RC[rc_idx]);
    if b {
        wrapping_add(x_plus_sqr, ROUND_CONSTANTS[rc_idx])
    } else {
        reduce_3p(tmp)
    }
}

// #[inline(always)]
fn x0p_plus_sqr1p_plus_rc_eq0p(x: [u64; 4], sqr: [u64; 4], rc_idx: usize) -> [u64; 4] {
    let x_plus_sqr = wrapping_add(x, sqr);
    let (tmp, b) = overflowing_sub(x_plus_sqr, MODULUS_1_MINUS_RC[rc_idx]);
    if b {
        wrapping_add(x_plus_sqr, ROUND_CONSTANTS[rc_idx])
    } else {
        reduce_2p(tmp)
    }
}

#[inline(always)]
fn x0p_plus_sqr1p_plus_y0p_eq0p(x: [u64; 4], sqr: [u64; 4], y: [u64; 4]) -> [u64; 4] {
    let x_plus_sqr = wrapping_add(x, sqr);
    let tmp = wrapping_add(x_plus_sqr, y);
    reduce_3p(tmp)
}

fn less_than(l: [u64; 4], r: [u64; 4]) -> bool {
    use core::cmp::Ordering;
    for (l, r) in l.iter().rev().zip(r.iter().rev()) {
        match l.cmp(r) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use {super::*, proptest::proptest};

    #[test]
    fn eq_ref() {
        proptest!(|(l: [u64; 4], r: [u64; 4])| {
            let e = crate::reference::compress(l, r);
            let r = compress(l, r);
            assert_eq!(r, e);
        });
    }
}
