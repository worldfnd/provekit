use noir_r1cs::{
    utils::{next_power_of_two, sumcheck::SumcheckIOPattern},
    IOPattern, R1CS,
};

pub fn create_io_pattern(r1cs: &R1CS) -> IOPattern {
    IOPattern::new("💥").add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
}
