use {crate::FieldElement, ark_ff::UniformRand, whir::poly_utils::evals::EvaluationsList};

pub fn create_masked_polynomial(
    original: &EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> Vec<FieldElement> {
    let mut rng = ark_std::rand::thread_rng();
    let mut elements = Vec::with_capacity(1 << num_vars);

    for _ in 0..(1 << num_vars) {
        elements.push(FieldElement::rand(&mut rng));
    }

    elements
}
