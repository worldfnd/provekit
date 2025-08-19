use {noir_r1cs::R1CS, std::fs};

fn main() {
    let json_str = fs::read_to_string("spark/spark-prover/r1cs.json")
        .expect("Error: Failed to open the r1cs.json file");
    let r1cs: R1CS =
        serde_json::from_str(&json_str).expect("Error: Failed to deserialize JSON to R1CS");
}
