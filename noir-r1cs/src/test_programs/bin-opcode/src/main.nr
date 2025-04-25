fn main(w: u32, x: u32, y: u32, z: u32) -> pub u32 {
    let hi = x & x ^ y & y & z & z ^ w & w;
    let bye = x & (31 as u32);
    let rye = y ^ (64 as u32);
    bye & rye ^ hi
}
