use ::{
    provekit_common::{FieldElement, R1CS},
    std::{fs::File, io::Write},
};

fn main() {
    let mut r1cs = R1CS::new();
    r1cs.grow_matrices(256, 256);
    let interned_1 = r1cs.interner.intern(FieldElement::from(1));
    let interned_2 = r1cs.interner.intern(FieldElement::from(2));
    let interned_3 = r1cs.interner.intern(FieldElement::from(3));

    for i in 0..256 {
        r1cs.a.set(i, i, interned_1);
        r1cs.b.set(i, i, interned_2);
        r1cs.c.set(i, i, interned_3);
    }

    r1cs.a.set(1, 0, interned_1);
    r1cs.a.set(2, 0, interned_1);
    r1cs.a.set(3, 0, interned_1);

    let matrix_json =
        serde_json::to_string(&r1cs).expect("Error: Failed to serialize R1CS to JSON");
    let mut request_file =
        File::create("r1cs.json").expect("Error: Failed to create the r1cs.json file");
    request_file
        .write_all(matrix_json.as_bytes())
        .expect("Error: Failed to write JSON data to r1cs.json");

    println!("Generated r1cs.json");
}
