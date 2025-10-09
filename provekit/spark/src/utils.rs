pub use crate::types::{Memory, Point, SPARKRequest};
use ::{
    anyhow::{Context, Result},
    provekit_common::{
        utils::{next_power_of_two, sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq},
        FieldElement, R1CS,
    },
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    std::{fs, path::Path},
};

/// Deserializes R1CS from JSON and pads matrices to power-of-2 dimensions.
pub fn deserialize_r1cs(path: impl AsRef<Path>) -> Result<R1CS> {
    let json_str = fs::read_to_string(path).context("Failed to read R1CS file")?;
    let mut r1cs: R1CS = serde_json::from_str(&json_str).context("Failed to deserialize R1CS")?;
    r1cs.grow_matrices(
        1 << next_power_of_two(r1cs.num_constraints()),
        1 << next_power_of_two(r1cs.num_witnesses()),
    );
    Ok(r1cs)
}

/// Deserializes SPARK request from JSON.
pub fn deserialize_request(path: impl AsRef<Path>) -> Result<SPARKRequest> {
    let json_str = fs::read_to_string(path).context("Failed to read request file")?;
    serde_json::from_str(&json_str).context("Failed to deserialize request")
}

/// Computes equality check evaluations for row and column points.
pub fn calculate_memory(point_to_evaluate: Point) -> Memory {
    Memory {
        eq_rx: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.row),
        eq_ry: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.col[1..])
            .iter()
            .map(|x| *x * (FieldElement::from(1) - point_to_evaluate.col[0]))
            .collect(),
    }
}

/// Trait extending IO patterns with SPARK-specific domain separators.
pub trait SPARKDomainSeparator {
    fn add_tau_and_gamma(self) -> Self;
    fn add_line(self) -> Self;
    fn add_claimed_evaluations(self) -> Self;
}

impl<IOPattern> SPARKDomainSeparator for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_tau_and_gamma(self) -> Self {
        self.challenge_scalars(2, "tau and gamma")
    }

    fn add_line(self) -> Self {
        self.add_scalars(2, "gpa line")
            .challenge_scalars(1, "gpa line random")
    }

    fn add_claimed_evaluations(self) -> Self {
        self.add_scalars(3, "claimed evaluations")
            .challenge_scalars(1, "matrix combination randomness")
    }
}
