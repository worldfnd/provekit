use {
    crate::whir::SPARKWHIRConfigs, noir_r1cs::{
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern}, FieldElement, IOPattern, R1CS
    }, spongefish::codecs::arkworks_algebra::FieldDomainSeparator, whir::whir::domainsep::WhirDomainSeparator
};

pub trait SPARKDomainSeparator {
    fn add_tau_and_gamma(self) -> Self;
}


impl<IOPattern> SPARKDomainSeparator for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_tau_and_gamma(self) -> Self {
        self.challenge_scalars(2, "tau and gamma")
    }
}


pub fn create_io_pattern (r1cs: &R1CS, configs: &SPARKWHIRConfigs) -> IOPattern {
    IOPattern::new("💥")
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
        .hint("sumcheck_last_folds")
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
        .add_tau_and_gamma()
}
