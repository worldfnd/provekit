use {
    crate::whir::SPARKWHIRConfigs,
    noir_r1cs::{
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern},
        IOPattern, R1CS,
    },
    whir::whir::domainsep::WhirDomainSeparator,
};

pub fn create_io_pattern(r1cs: &R1CS, configs: &SPARKWHIRConfigs) -> IOPattern {
    IOPattern::new("💥")
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
        .hint("sumcheck_last_folds")
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
}
