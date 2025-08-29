use {provekit_common::FieldElement, spongefish::codecs::arkworks_algebra::FieldDomainSeparator};

/// Trait which is used to add witness RNG for IOPattern
pub trait WitnessIOPattern {
    /// Schedule absorption of circuit shape (2 scalars): (num_constraints,
    /// num_witnesses).
    fn add_shape(self) -> Self;

    /// Schedule absorption of `num_pub_inputs` public input scalars.
    fn add_public_inputs(self, num_pub_inputs: usize) -> Self;

    /// Schedule absorption of `num_challenges` Fiat–Shamir challenges for
    /// LogUp/Spice.
    fn add_logup_challenges(self, num_challenges: usize) -> Self;
}

impl<IOPattern> WitnessIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_shape(self) -> Self {
        self.add_scalars(2, "shape")
    }

    fn add_public_inputs(self, num_pub_inputs: usize) -> Self {
        if num_pub_inputs > 0 {
            self.add_scalars(num_pub_inputs, "pub_inputs")
        } else {
            self
        }
    }

    fn add_logup_challenges(self, num_challenges: usize) -> Self {
        if num_challenges > 0 {
            self.challenge_scalars(num_challenges, "wb:challenges")
        } else {
            self
        }
    }
}
