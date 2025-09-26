use {
    crate::whir::SPARKWHIRConfigs,
    provekit_common::{
        utils::{next_power_of_two, sumcheck::SumcheckIOPattern},
        FieldElement, IOPattern, R1CS,
    },
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    whir::whir::domainsep::WhirDomainSeparator,
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

pub fn create_io_pattern(r1cs: &R1CS, configs: &SPARKWHIRConfigs) -> IOPattern {
    let mut io = IOPattern::new("💥");

    // Matrix A

    io = io
        .commit_statement(&configs.a_3batched)
        .commit_statement(&configs.a_3batched)
        .commit_statement(&configs.a_3batched)
        .commit_statement(&configs.row)
        .commit_statement(&configs.col)
        .add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
        .hint("sumcheck_last_folds");
        // .add_whir_proof(&configs.a_3batched);
    
    // Rowwise

    io = io.add_tau_and_gamma();

    for i in 0..=next_power_of_two(r1cs.a.num_rows) {
        io = io.add_sumcheck_polynomials(i);
        io = io.add_line();
    }

    // io = io
    //     .hint("Row final counter claimed evaluation")
    //     .add_whir_proof(&configs.row);

    // for i in 0..=next_power_of_two(r1cs.a.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.a_3batched);

    // // Colwise

    // io = io.add_tau_and_gamma();

    // for i in 0..=next_power_of_two(r1cs.a.num_cols) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("Col final counter claimed evaluation")
    //     .add_whir_proof(&configs.col);

    // for i in 0..=next_power_of_two(r1cs.a.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.a_3batched);

    // // Matrix B

    // io = io
    //     .commit_statement(&configs.b_3batched)
    //     .commit_statement(&configs.b_3batched)
    //     .commit_statement(&configs.b_3batched)
    //     .commit_statement(&configs.row)
    //     .commit_statement(&configs.col)
    //     .add_sumcheck_polynomials(next_power_of_two(r1cs.a.num_entries()))
    //     .hint("sumcheck_last_folds")
    //     .add_whir_proof(&configs.b_3batched);
    
    // // Rowwise

    // io = io.add_tau_and_gamma();

    // for i in 0..=next_power_of_two(r1cs.b.num_rows) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("Row final counter claimed evaluation")
    //     .add_whir_proof(&configs.row);

    // for i in 0..=next_power_of_two(r1cs.b.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.b_3batched);

    // // Colwise

    // io = io.add_tau_and_gamma();

    // for i in 0..=next_power_of_two(r1cs.b.num_cols) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("Col final counter claimed evaluation")
    //     .add_whir_proof(&configs.col);

    // for i in 0..=next_power_of_two(r1cs.b.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.b_3batched);

    // // Matrix C

    // io = io
    //     .commit_statement(&configs.c_3batched)
    //     .commit_statement(&configs.c_3batched)
    //     .commit_statement(&configs.c_3batched)
    //     .commit_statement(&configs.row)
    //     .commit_statement(&configs.col)
    //     .add_sumcheck_polynomials(next_power_of_two(r1cs.c.num_entries()))
    //     .hint("sumcheck_last_folds")
    //     .add_whir_proof(&configs.c_3batched);
    
    // // Rowwise

    // io = io.add_tau_and_gamma();

    // for i in 0..=next_power_of_two(r1cs.c.num_rows) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("Row final counter claimed evaluation")
    //     .add_whir_proof(&configs.row);

    // for i in 0..=next_power_of_two(r1cs.c.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.c_3batched);

    // // Colwise

    // io = io.add_tau_and_gamma();

    // for i in 0..=next_power_of_two(r1cs.c.num_cols) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("Col final counter claimed evaluation")
    //     .add_whir_proof(&configs.col);

    // for i in 0..=next_power_of_two(r1cs.c.num_entries()) {
    //     io = io.add_sumcheck_polynomials(i);
    //     io = io.add_line();
    // }

    // io = io
    //     .hint("RS address claimed evaluation")
    //     .hint("RS value claimed evaluation")
    //     .hint("RS timestamp claimed evaluation")
    //     .add_whir_proof(&configs.c_3batched);
    io
}
