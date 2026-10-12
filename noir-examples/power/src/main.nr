// x^10 == y, returning the power as the public result.
fn main(mut x: Field, y: pub Field) -> pub Field {
  let mut r = 1;
  for i in 0..10 {
    r *= x;
  }
  assert(r == y);
  r
}
