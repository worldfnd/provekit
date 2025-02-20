use whir::crypto::fields::Field256;
use nimue::plugins::ark::FieldIOPattern;

/// Given evaluations over boolean hypercube, replace the first variable with given value and calculate new evaluations (Fold boolean hypercube over a given value)
pub fn update_boolean_hypercube_values(mut f: Vec<Field256>, r: Field256) -> Vec<Field256> {
    let sz = f.len();
    let (left, right) = f.split_at_mut(sz / 2);
    for i in 0..(left.len()) {
        left[i] += r * (right[i]-left[i]);
    }
    left.to_vec()
}

/// Trait which is used to add sumcheck functionality fo IOPattern
pub trait SumcheckIOPattern {
    /// Prover sends coefficients of the qubic sumcheck polynomial and the verifier sends randomness for the next sumcheck round
    fn add_sumcheck_polynomials(self, num_vars: usize) -> Self;
    
    /// Verifier sends the randomness on which the supposed 0-polynomial is evaluated
    fn add_rand(self, num_rand: usize) -> Self;
}

impl<IOPattern> SumcheckIOPattern for IOPattern 
where 
    IOPattern: FieldIOPattern<Field256>
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