use core::cmp::Ordering;

#[inline(always)]
pub fn add(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (r, carry) = overflowing_add(l, r);
    debug_assert!(!carry);
    r
}

#[inline(always)]
pub fn sub(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let (r, borrow) = overflowing_sub(l, r);
    debug_assert!(!borrow);
    r
}

#[inline(always)]
pub fn wrapping_add(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    overflowing_add(l, r).0
}

#[inline(always)]
pub fn wrapping_sub(l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    overflowing_sub(l, r).0
}

#[inline(always)]
pub fn overflowing_add(l: [u64; 4], r: [u64; 4]) -> ([u64; 4], bool) {
    let (r0, carry) = l[0].overflowing_add(r[0]);
    let (r1, carry) = l[1].carrying_add(r[1], carry);
    let (r2, carry) = l[2].carrying_add(r[2], carry);
    let (r3, carry) = l[3].carrying_add(r[3], carry);
    ([r0, r1, r2, r3], carry)
}

#[inline(always)]
pub fn overflowing_sub(l: [u64; 4], r: [u64; 4]) -> ([u64; 4], bool) {
    let (r0, borrow) = l[0].overflowing_sub(r[0]);
    let (r1, borrow) = l[1].borrowing_sub(r[1], borrow);
    let (r2, borrow) = l[2].borrowing_sub(r[2], borrow);
    let (r3, borrow) = l[3].borrowing_sub(r[3], borrow);
    ([r0, r1, r2, r3], borrow)
}

pub fn less_than(l: [u64; 4], r: [u64; 4]) -> bool {
    for (l, r) in l.iter().rev().zip(r.iter().rev()) {
        match l.cmp(r) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    false
}
