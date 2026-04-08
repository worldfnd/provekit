fn main(mut x: Field, y: pub Field) {
  let mut r = 1;
  for _ in 0..1000 {
    r *= x;
  }
  assert(r == y);
}
