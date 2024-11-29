fn main(a: Field, b: pub Field, c: pub Field, d: pub Field) {
    assert(a * b + c == d);
}

#[test]
fn test_main() {
    main(1, 2, 3, 5);
}

// use dep::poseidon2;

// fn main(plains: [Field; 8]) -> pub Field {
//     poseidon2::bn254::hash_8(plains)
// }
