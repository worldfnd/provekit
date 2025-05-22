fn main(x: Field, y: Field) {
    assert(x - y == 0);
    let z = x + y;
    let k = z + 2;
    let p = k * k;
    let y = p * p;
    assert(y == k * k * k * k);
    let t = k * y;
    assert(t == (z + 2) * k * k * k * k)
}
