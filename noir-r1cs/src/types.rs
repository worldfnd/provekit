use acir::circuit::Program as ACIRProgram;
// pub use acir_field::AcirField;
pub use acir_field::FieldElement;

pub type Program = ACIRProgram<FieldElement>;
