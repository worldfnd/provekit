// Type your code here, or load an example.

// As of Rust 1.75, small functions are automatically
// marked as `#[inline]` so they will not show up in
// the output when compiling with optimisations. Use
// `#[no_mangle]` or `#[inline(never)]` to work around
// this issue.
// See https://github.com/compiler-explorer/compiler-explorer/issues/5939
use std::hint::black_box;
// If you use `main()`, declare it as `pub` to see it in the output:
pub fn main() {
    let (lo, hi) = (u32::carrying_mul_add(black_box(5), black_box(6), 0, 0));
    let _res = black_box(2 * hi + lo);
}
