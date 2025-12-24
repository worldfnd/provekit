use {crate::FieldElement, spongefish::codecs::arkworks_algebra::FieldDomainSeparator};

/// Trait which is used to add witness RNG for IOPattern
pub trait WitnessIOPattern {
    /// Schedule absorption of `num_challenges` Fiat–Shamir challenges for
    /// LogUp/Spice.
    fn add_logup_challenges(self, num_challenges: usize) -> Self;
}

impl<IOPattern> WitnessIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_logup_challenges(self, num_challenges: usize) -> Self {
        if num_challenges > 0 {
            self.challenge_scalars(num_challenges, "wb:challenges")
        } else {
            self
        }
    }
}
