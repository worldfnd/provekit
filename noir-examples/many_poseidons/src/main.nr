use poseidon::poseidon::bn254;

fn main(mut input: Field, out: pub Field) {
    for i in 0..10 {
      input = bn254::hash_1([input]);
    }
    assert_eq(input, out);
}
