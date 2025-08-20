use {
    noir_r1cs::{FieldElement, R1CS},
    spark_prover::utilities::{ClaimedValues, Point, SPARKRequest},
    std::{fs::File, io::Write},
};

fn main() {
    let spark_request = SPARKRequest {
        point_to_evaluate: Point {
            row: vec![FieldElement::from(0); 1024],
            col: vec![FieldElement::from(0); 512],
        },
        claimed_values:    ClaimedValues {
            a: FieldElement::from(1),
            b: FieldElement::from(1),
            c: FieldElement::from(1),
        },
    };

    let request_json =
        serde_json::to_string(&spark_request).expect("Error: Failed to serialize R1CS to JSON");
    let mut request_file = File::create("spark/spark-prover/request.json")
        .expect("Error: Failed to create the request.json file");
    request_file
        .write_all(request_json.as_bytes())
        .expect("Error: Failed to write JSON data to request.json");
}
