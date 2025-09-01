use {
    divan::black_box,
    fp_rounding::{with_rounding_mode, Zero},
};

fn main() {
    divan::main();
}

#[divan::bench()]
fn wrm_overhead() {
    unsafe { with_rounding_mode::<Zero, _, _>((), |_guard, a| black_box(a)) }
}
