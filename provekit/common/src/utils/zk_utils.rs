use {
    crate::FieldElement, ark_ff::UniformRand, rayon::prelude::*,
    whir::poly_utils::evals::EvaluationsList,
};

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
    let num_elements = 1 << num_vars;

    // Generate random elements in parallel
    (0..num_elements)
        .into_par_iter()
        .map(|_| {
            let mut rng = ark_std::rand::thread_rng();
            FieldElement::rand(&mut rng)
        })
        .collect()
}
