use whir::crypto::fields::Field256;
use itertools::izip;
use crate::skyscraper::skyscraper::SkyscraperSponge;
use nimue::Merlin;
use crate::utils::{
    HALF,
    next_power_of_two,
};
use nimue::plugins::ark::FieldWriter;
use nimue::plugins::ark::FieldChallenges;
use nimue::plugins::ark::FieldIOPattern;
use crate::utils::evaluations_over_boolean_hypercube_for_eq;


pub fn update_boolean_hypercube_values_with_r(mut f: Vec<Field256>, r: Field256) -> Vec<Field256> {
    let sz = f.len();
    let (left, right) = f.split_at_mut(sz / 2);
    for i in 0..(left.len()) {
        // println!("Before {:?} {:?} {:?}", left[i], r, right[i]-left[i]);
        left[i] += r * (right[i]-left[i]);
        // println!("After {:?}", left[i]);
    }
    left.to_vec()
}

pub fn prove_sumcheck(
    mut a: Vec<Field256>,
    mut b: Vec<Field256>,
    mut c: Vec<Field256>,
    mut sum: Field256,
    mut merlin: Merlin<SkyscraperSponge, Field256>,
    log_constraints: usize,
) -> Merlin<SkyscraperSponge, Field256> {

    let mut rand = vec![Field256::from(0); log_constraints];
    let _ = merlin.fill_challenge_scalars(&mut rand);
    let mut eq = evaluations_over_boolean_hypercube_for_eq(rand);

    for i in 0..next_power_of_two(a.len()) {
        println!("---------------- For iteration {:?} ----------------", i);
        println!("A: {:?}", a);
        println!("B: {:?}", b); 
        println!("C: {:?}", c);
        println!("EQ: {:?}", eq);
        
        let mut eval_at_0 = Field256::from(0);
        let mut eval_at_em1 = Field256::from(0);
        let mut eval_at_inf = Field256::from(0);
        
        let (a0, a1) = a.split_at(a.len() / 2);
        let (b0, b1) = b.split_at(b.len() / 2);
        let (c0, c1) = c.split_at(c.len() / 2);
        let (eq0, eq1) = eq.split_at(eq.len() / 2);
        
        izip!(
            a0.iter().zip(a1),
            b0.iter().zip(b1),
            c0.iter().zip(c1),
            eq0.iter().zip(eq1)
        )
        .for_each(|(a, b, c, eq)| {
            eval_at_0 += *eq.0 * (a.0 * b.0 - c.0);
            eval_at_em1 += (eq.0 + eq.0 - eq.1) * ((a.0 + a.0 - a.1) * (b.0 + b.0 - b.1) - (c.0 + c.0 - c.1));
            eval_at_inf += (eq.1 - eq.0) * (a.1 - a.0) * (b.1 - b.0);
        });

        let p0 = eval_at_0;
        let p2 = HALF * (eval_at_em1 - eval_at_0 - eval_at_0 - eval_at_0);
        let p3 = eval_at_inf;
        let p1 = sum - p0 - p0 - p3 - p2;

        let _ = merlin.add_scalars(&vec![p0, p1, p2, p3]);
        let mut r = vec![Field256::from(0)];
        let _ = merlin.fill_challenge_scalars(&mut r);

        eq = update_boolean_hypercube_values_with_r(eq, r[0]);
        a = update_boolean_hypercube_values_with_r(a, r[0]);
        b = update_boolean_hypercube_values_with_r(b, r[0]);
        c = update_boolean_hypercube_values_with_r(c, r[0]);
        
        println!("Eval at 0: {:?}", p0);
        println!("Eval at 1: {:?}", p0 + p1 + p2 + p3);
        println!("Supposed sum: {:?}", sum);
        sum = p0 + r[0] * (p1 + r[0] * (p2 + r[0] * p3));
        println!("Actual sum: {:?}", p0 + p0 + p1 + p2 + p3); 
    }
    println!("Eval at rand: {:?}", sum);
    merlin
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