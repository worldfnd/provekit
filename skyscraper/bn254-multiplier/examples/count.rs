use bn254_multiplier::rne::{
    make_initial,
    single::{simd_mul, simd_sqr},
};

const LO: usize = 1;
const HI: usize = 1 << 16;

fn main() {
    let t = diagonal();
    for (i, x) in t.iter().enumerate() {
        println!("t[{i}]: lo: {}\t hi: {}", x & (HI - 1), x >> 16);
    }

    let a = [0, 0, 0, 0];
    let res = simd_sqr(a);
    for (i, k) in res.iter().enumerate() {
        println!("res[{i}]: {:x}", k)
    }

    println!("\nFULL");

    let t = full();
    for (i, x) in t.iter().enumerate() {
        let lo = x & (HI - 1);
        let hi = x >> 16;
        println!(
            "t[{i}]: lo: {}\t hi: {}\t init: {:x}",
            lo,
            hi,
            make_initial(lo as u64, hi as u64)
        );
    }

    let a = [0, 0, 0, 0];
    let res = simd_mul(a, a);
    for (i, k) in res.iter().enumerate() {
        println!("res[{i}]: {:x}", k)
    }
}

fn diagonal() -> [usize; 12] {
    let mut t = [0; 12];
    for i in 0..5 {
        for j in ((i + 1)..5).step_by(2) {
            println!("i: {i} j: {} {}", j, j + 1);
            t[i + j + 2] += HI;
            t[i + j + 1] += LO + HI;
            t[i + j] += LO;
        }
        println!();
    }

    // scalar doubling
    // needs to chop off the 1 in 01 and the 8 in 89 and feed it back into 12 and 78
    // respectively.
    // for i in 1..=8 {
    //     t[i] += t[i];
    // }

    for i in (0..4).step_by(2) {
        t[2 * (i + 1) + 1] += HI;
        t[2 * (i + 1)] += LO;
        t[2 * i + 1] += HI;
        t[2 * i] += LO;
    }
    t[2 * 4 + 1] += HI;
    t[2 * 4] += LO;

    let i = 4;
    for _k in 0..5 {
        for j in 0..3 {
            t[i + 2 * j + 2] += HI;
            t[i + 2 * j + 1] += LO + HI;
            t[i + 2 * j] += LO;
        }
    }

    t
}

fn full() -> [usize; 11] {
    let mut t = [0; 11];
    for i in 0..5 {
        for j in 0..3 {
            t[i + 2 * j + 2] += HI;
            t[i + 2 * j + 1] += LO + HI;
            t[i + 2 * j] += LO;
        }
    }

    let i = 4;
    for _k in 0..5 {
        for j in 0..3 {
            t[i + 2 * j + 2] += HI;
            t[i + 2 * j + 1] += LO + HI;
            t[i + 2 * j] += LO;
        }
    }

    t
}
