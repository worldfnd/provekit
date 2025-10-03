use {provekit_common::FieldElement, spongefish::codecs::arkworks_algebra::FieldDomainSeparator};

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
