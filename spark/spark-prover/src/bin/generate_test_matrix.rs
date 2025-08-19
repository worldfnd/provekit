use {
    noir_r1cs::{FieldElement, R1CS},
    std::{fs::File, io::Write},
};

fn main() {
    let mut r1cs = R1CS::new();
    r1cs.grow_matrices(1024, 512);
    let interned_1 = r1cs.interner.intern(FieldElement::from(1));

    r1cs.a.set(0, 0, interned_1);
    r1cs.a.set(0, 1, interned_1);
    r1cs.a.set(1, 0, interned_1);

    let json = serde_json::to_string(&r1cs).expect("Error: Failed to serialize R1CS to JSON");
    let mut r1cs_file =
        File::create("spark/spark-prover/r1cs.json").expect("Error: Failed to create the r1cs.json file");
    r1cs_file
        .write_all(json.as_bytes())
        .expect("Error: Failed to write JSON data to r1cs.json");
}
