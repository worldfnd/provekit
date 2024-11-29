use {crate::poseidon, ark_bn254::Fr, ark_ff::MontFp};

// Random initial state (nothing up my sleeve: digits of 2 * pi in groups of 77
// digits)
const INITIAL_STATE: [Fr; 3] = [
    MontFp!("62831853071795864769252867665590057683943387987502116419498891846156328125724"),
    MontFp!("17997256069650684234135964296173026564613294187689219101164463450718816256962"),
    MontFp!("23490056820540387704221111928924589790986076392885762195133186689225695129646"),
];

pub struct Sponge {
    state:  [Fr; 3],
    sponge: SpongeState,
}

// Sponge with rate 2 and capacity 1
enum SpongeState {
    Initial,
    Absorbing,
    Squeezing,
    Full,
}

impl Sponge {
    pub fn new() -> Self {
        Self {
            state:  INITIAL_STATE,
            sponge: SpongeState::Initial,
        }
    }

    pub fn absorb(&mut self, value: Fr) {
        match self.sponge {
            SpongeState::Initial => {
                self.state[0] += value;
                self.sponge = SpongeState::Absorbing;
            }
            SpongeState::Absorbing => {
                self.state[1] += value;
                self.sponge = SpongeState::Full;
            }
            SpongeState::Full | SpongeState::Squeezing => {
                poseidon::permute_3(&mut self.state);
                self.state[0] += value;
                self.sponge = SpongeState::Absorbing;
            }
        }
    }

    pub fn squeeze(&mut self) -> Fr {
        match self.sponge {
            SpongeState::Initial => {
                self.sponge = SpongeState::Squeezing;
                self.state[0]
            }
            SpongeState::Squeezing => {
                self.sponge = SpongeState::Full;
                self.state[1]
            }
            SpongeState::Full | SpongeState::Absorbing => {
                poseidon::permute_3(&mut self.state);
                self.sponge = SpongeState::Squeezing;
                self.state[0]
            }
        }
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Sponge::new()
    }
}
