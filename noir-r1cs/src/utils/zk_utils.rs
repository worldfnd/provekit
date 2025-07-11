use {
    crate::FieldElement,
    ark_ff::UniformRand,
    ark_std::Zero,
    whir::poly_utils::{coeffs::CoefficientList, evals::EvaluationsList},
};

pub fn generate_zero_sum_mask(num_vars: usize) -> Vec<FieldElement> {
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
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(&original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> CoefficientList<FieldElement> {
    let mut rng = ark_std::rand::thread_rng();
    let mut coeffs = Vec::with_capacity(1 << num_vars);

    for _ in 0..(1 << num_vars) {
        coeffs.push(FieldElement::rand(&mut rng));
    }

    CoefficientList::new(coeffs)
}

pub fn create_virtual_polynomial(
    masked_poly: &CoefficientList<FieldElement>,
    random_poly: &CoefficientList<FieldElement>,
    rho: FieldElement,
) -> CoefficientList<FieldElement> {
    assert_eq!(
        masked_poly.num_variables(),
        random_poly.num_variables(),
        "Polynomials must have the same number of variables"
    );

    let size = masked_poly.num_coeffs();
    let mut virtual_coeffs = Vec::with_capacity(size);

    let masked_coeffs = masked_poly.coeffs();
    let random_coeffs = random_poly.coeffs();

    for i in 0..size {
        let virtual_coeff = rho * masked_coeffs[i] + random_coeffs[i];
        virtual_coeffs.push(virtual_coeff);
    }

    CoefficientList::new(virtual_coeffs)
}
