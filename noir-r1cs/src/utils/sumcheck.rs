use {
    crate::{utils::pad_to_power_of_two, FieldElement, R1CS},
    ark_std::One,
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    tracing::instrument,
    whir::crypto::fields::Field256,
};

/// Given evaluations over boolean hypercube, replace the first variable with
/// given value and calculate new evaluations (Fold boolean hypercube over a
/// given value)
pub fn update_boolean_hypercube_values(mut f: Vec<Field256>, r: Field256) -> Vec<Field256> {
    let sz = f.len();
    let (left, right) = f.split_at_mut(sz / 2);
    for i in 0..(left.len()) {
        left[i] += r * (right[i] - left[i]);
    }
    left.to_vec()
}

/// Trait which is used to add sumcheck functionality fo IOPattern
pub trait SumcheckIOPattern {
    /// Prover sends coefficients of the qubic sumcheck polynomial and the
    /// verifier sends randomness for the next sumcheck round
    fn add_sumcheck_polynomials(self, num_vars: usize) -> Self;

    /// Verifier sends the randomness on which the supposed 0-polynomial is
    /// evaluated
    fn add_rand(self, num_rand: usize) -> Self;
}

impl<IOPattern> SumcheckIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<Field256>,
{
    fn add_sumcheck_polynomials(mut self, num_vars: usize) -> Self {
        for _ in 0..num_vars {
            self = self.add_scalars(4, "Sumcheck Polynomials");
            self = self.challenge_scalars(1, "Sumcheck Random");
        }
        self
    }

    fn add_rand(self, num_rand: usize) -> Self {
        self.challenge_scalars(num_rand, "rand")
    }
}

/// List of evaluations for eq(r, x) over the boolean hypercube
#[instrument(skip_all)]
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &Vec<FieldElement>,
) -> Vec<FieldElement> {
    let mut ans = vec![FieldElement::from(1)];
    for x in r.iter().rev() {
        let mut left: Vec<FieldElement> = ans
            .clone()
            .into_iter()
            .map(|y| y * (FieldElement::one() - x))
            .collect();
        let right: Vec<FieldElement> = ans.into_iter().map(|y| y * x).collect();
        left.extend(right);
        ans = left;
    }
    ans
}

/// Evaluates a qubic polynomial on a value
pub fn eval_qubic_poly(poly: &Vec<FieldElement>, point: &FieldElement) -> FieldElement {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

/// Given a path to JSON file with sparce matrices and a witness, calculates
/// matrix-vector multiplication and returns them
#[instrument(skip_all)]
pub fn calculate_witness_bounds(
    r1cs: &R1CS,
    witness: &[FieldElement],
) -> (Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>) {
    let witness_bound_a = pad_to_power_of_two(&r1cs.a * witness);
    let witness_bound_b = pad_to_power_of_two(&r1cs.b * witness);
    let witness_bound_c = pad_to_power_of_two(&r1cs.c * witness);
    (witness_bound_a, witness_bound_b, witness_bound_c)
}

/// Calculates eq(r, alpha)
pub fn calculate_eq(r: &[FieldElement], alpha: &[FieldElement]) -> FieldElement {
    r.iter()
        .zip(alpha.iter())
        .fold(FieldElement::from(1), |acc, (&r, &alpha)| {
            acc * (r * alpha + (FieldElement::from(1) - r) * (FieldElement::from(1) - alpha))
        })
}

/// Calculates a random row of R1CS matrix extension. Made possible due to
/// sparseness.
#[instrument(skip_all)]
pub fn calculate_external_row_of_r1cs_matrices(
    alpha: &Vec<FieldElement>,
    r1cs: &R1CS,
) -> [Vec<FieldElement>; 3] {
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let eq_alpha = &eq_alpha[..r1cs.constraints];
    [eq_alpha * &r1cs.a, eq_alpha * &r1cs.b, eq_alpha * &r1cs.c]
}
