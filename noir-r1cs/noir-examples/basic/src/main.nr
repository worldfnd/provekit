// fn main(a: Field, b: pub Field, c: pub Field, d: pub Field) {
//     assert(2 * a * b - (d + 2) * c == d * 5);
// }

// fn main(e: Field, f: pub Field, g: pub Field, h: pub Field) {
//     assert(e * f + h * g == (h + 1) * 5);
// }

fn main(i: Field, j: pub Field, k: pub Field, l: pub Field) {
    assert(3 * i * j * l + 2 * (k + 1) * (l + 5) + 1 == (l + 13) * 5);
    assert((i + j) * k * l + (j - i) * (k + l) == 48);
    assert(j * j - i * k * l + (l + k) * (i + j) == 78);
    assert((i * j + k) * (l + 2) - j == 23);
    // Complex nested operations with multiple terms
    assert((i * j * j + k * k) * (l + i) + (j - k) * (j + k) == 156);

    // Using squares and products with multiple groupings
    assert((j * j * j - k * k * i) * l + (i + l) * (j + k) == 354);

    // Multiple groups with mixed operations
    assert((i + j) * (j - k) * (k + l) + (j * j - i) * (k - l) == 224);

    // Nested multiplications with additions and subtractions
    assert((((i + j) * k - l) * (j - k) + i) * (l + k) == 372);

    // Very complex grouping with multiple terms
    assert((i * j + k * l) * (j * j - k) + (l + i) * (j - k) * (k + i) == 492);

    // Using differences of squares pattern with extra terms
    assert((j + k) * (j - k) + (i * l) * (j * j - k * k) + l == 81);

    // Complex polynomial with nested terms
    assert((j * j * j - k * k * i) * (l + i) + (j * k - i) * (j * j - k * l) == 1588);

    // Nested products with multiple groupings and differences
    assert((j * j + k * i) * (j - k) * (l + k) - (i + l) * (k * k * j) == 706);

    // Complex cubic terms with mixed operations
    assert((j + k) * (j * j - k * k) * (l + i) + (j - i) * k * (k + l) == 872);

    // Multiple nested groups with squares and products
    assert((j * j - i) * (k * k + l) * (j - k) + (i + l) * (j * k - l) == 1960);

    // Complex differences with cubic terms
    assert((j * j * j - k * k * k) * (l + i) - (j - k) * (j + k) * (j * l) == 352);

    // Nested operations with multiple factors
    assert((j * k + i * l) * (j * j - k * l) * (k + i) - (j - l) * k * k == 3994);
}

#[test]
fn test_main() {
    main(1, 2, 3, 5);
}

// use dep::poseidon2;

// fn main(plains: [Field; 8]) -> pub Field {
//     poseidon2::bn254::hash_8(plains)
// }
