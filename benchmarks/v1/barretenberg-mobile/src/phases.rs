/// The only backend identity accepted by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backend;

impl Backend {
    pub const VERSION: &'static str = "0.87.0";
    pub const NOIR_VERSION: &'static str = "1.0.0-beta.11";
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Workload {
    PassportCompleteAgeCheck,
    WebAuthnAssertion,
    OprfTaceo,
}

impl Workload {
    pub const ALL: [Self; 3] = [
        Self::PassportCompleteAgeCheck,
        Self::WebAuthnAssertion,
        Self::OprfTaceo,
    ];

    pub const fn fixture_name(self) -> &'static str {
        match self {
            Self::PassportCompleteAgeCheck => "passport_complete_age_check",
            Self::WebAuthnAssertion => "webauthn_assertion",
            Self::OprfTaceo => "oprf_taceo",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Witness,
    Prove,
    Verify,
    EndToEnd,
}

impl Phase {
    pub const ALL: [Self; 4] = [Self::Witness, Self::Prove, Self::Verify, Self::EndToEnd];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_exposes_all_twelve_phase_cells() {
        let cells = Workload::ALL
            .into_iter()
            .flat_map(|workload| Phase::ALL.map(|phase| (workload, phase)))
            .count();
        assert_eq!(cells, 12);
        assert_eq!(Backend::VERSION, "0.87.0");
        assert_eq!(Backend::NOIR_VERSION, "1.0.0-beta.11");
    }
}
