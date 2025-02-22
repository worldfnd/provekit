// fn main(a: Field, b: pub Field, c: pub Field, d: pub Field) {
//     assert(2 * a * b - (d + 2) * c == d * 5);
// }

// fn main(e: Field, f: pub Field, g: pub Field, h: pub Field) {
//     assert(e * f + h * g == (h + 1) * 5);
// }

fn main(i: Field, j: pub Field, k: pub Field, l: pub Field) {
    assert(3 * i * j * l + 2 * (k + 1) * (l + 5) + 1 == (l + 13) * 5);
    // 3 * 7 = 21 + 2* 4 * 6 = 48 = 69 + 1= 70
}

#[test]
fn test_main() {
    main(1, 2, 3, 5);
}

// use dep::poseidon2;

// fn main(plains: [Field; 8]) -> pub Field {
//     poseidon2::bn254::hash_8(plains)
// }
