use file_vec::FileVec;
use {crate::FieldElement, ark_ff::UniformRand, whir::poly_utils::evals::EvaluationsList};

pub fn generate_mask(num_vars: usize) -> Vec<FieldElement> {
    let mut rng = ark_std::rand::thread_rng();
    let mut mask = Vec::with_capacity(num_vars);

    for _ in 0..num_vars {
        mask.push(FieldElement::rand(&mut rng));
    }

    mask
}

pub fn create_masked_polynomial(
    original: &EvaluationsList<FieldElement>,
    mask: &Vec<FieldElement>,
) -> EvaluationsList<FieldElement> {
    let mut combined = FileVec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(&original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> EvaluationsList<FieldElement> {
    let mut rng = ark_std::rand::thread_rng();
    let mut coeffs = FileVec::with_capacity(1 << num_vars);

    for _ in 0..(1 << num_vars) {
        coeffs.push(FieldElement::rand(&mut rng));
    }

    EvaluationsList::new(coeffs)
}
