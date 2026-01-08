use {
    crate::{hash::utils::bigint_from_bytes_le, FieldElement},
    ark_ff::{BigInt, PrimeField},
    sha2::{Digest, Sha256},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

fn field_to_bytes(f: FieldElement) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let limbs = f.into_bigint().0;
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn bytes_to_field(bytes: [u8; 32]) -> FieldElement {
    let limbs: [u64; 4] = [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ];
    FieldElement::from(BigInt::new(limbs))
}

pub fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let mut hasher = Sha256::new();
    hasher.update(field_to_bytes(l));
    hasher.update(field_to_bytes(r));
    let result: [u8; 32] = hasher.finalize().into();
    bytes_to_field(result)
}

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct Sha2Permutation {
    state: State,
}

impl AsRef<[FieldElement]> for Sha2Permutation {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Sha2Permutation {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Sha2Permutation {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        let new_left = self.state[1];
        let new_right = compress(self.state[0], self.state[1]);
        self.state = [new_left, new_right];
    }
}

pub type Sha2Sponge = DuplexSponge<Sha2Permutation>;
