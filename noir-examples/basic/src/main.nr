fn main(x: Field, y: pub Field) {
    assert(x * x * x == y);
}

#[test]
fn test_main() {
    main(4, 64);
    // Uncomment to make test fail
    // main(1, 1);
}
