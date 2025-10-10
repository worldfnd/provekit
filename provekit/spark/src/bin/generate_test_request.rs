use {
    provekit_common::{
        spark::{ClaimedValues, Point, SparkStatement},
        FieldElement,
    },
    std::{fs::File, io::Write},
};

fn main() {
    let mut row = vec![FieldElement::from(0); 8];
    let col = vec![FieldElement::from(0); 9];

    row[7] = FieldElement::from(1);

    let spark_request = SparkStatement {
        point_to_evaluate: Point { row, col },
        claimed_values:    ClaimedValues {
            a: FieldElement::from(1),
            b: FieldElement::from(0),
            c: FieldElement::from(0),
        },
    };

    let request_json =
        serde_json::to_string(&spark_request).expect("Error: Failed to serialize request to JSON");
    let mut request_file =
        File::create("request.json").expect("Error: Failed to create the request.json file");
    request_file
        .write_all(request_json.as_bytes())
        .expect("Error: Failed to write JSON data to request.json");

    println!("Generated request.json");
}
