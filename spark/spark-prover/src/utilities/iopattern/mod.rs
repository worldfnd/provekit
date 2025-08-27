use {
    crate::whir::SPARKWHIRConfigs, noir_r1cs::{
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern}, FieldElement, IOPattern, R1CS
    }, spongefish::codecs::arkworks_algebra::FieldDomainSeparator, whir::whir::domainsep::WhirDomainSeparator
};

pub trait SPARKDomainSeparator {
    fn add_tau_and_gamma(self) -> Self;
    
    fn add_line(self) -> Self;
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
}


pub fn create_io_pattern (r1cs: &R1CS, configs: &SPARKWHIRConfigs) -> IOPattern {
    let mut io = IOPattern::new("💥")
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .commit_statement(&configs.a)
        .add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
        .hint("sumcheck_last_folds")
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
        .add_whir_proof(&configs.a)
        .add_tau_and_gamma();

    for i in 0..=next_power_of_two(r1cs.a.num_rows) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    io    
}
