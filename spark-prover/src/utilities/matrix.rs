use provekit_common::FieldElement;

#[derive(Debug)]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}
#[derive(Debug)]
pub struct COOMatrix {
    pub row:   Vec<FieldElement>,
    pub col:   Vec<FieldElement>,
    pub val:   Vec<FieldElement>,
    pub val_a: Vec<FieldElement>,
    pub val_b: Vec<FieldElement>,
    pub val_c: Vec<FieldElement>,
}
#[derive(Debug)]
pub struct TimeStamps {
    pub read_row:  Vec<FieldElement>,
    pub read_col:  Vec<FieldElement>,
    pub final_row: Vec<FieldElement>,
    pub final_col: Vec<FieldElement>,
}
