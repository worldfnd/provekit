mod sponge;

pub use sponge::Sponge;
use {
    ark_bn254::{Fq, Fr, G1Affine},
    ark_ec::AffineRepr,
    ark_ff::PrimeField,
};

pub struct Prover {
    sponge:    Sponge,
    pub proof: Vec<Fr>,
}

pub struct Verifier<'a> {
    sponge: Sponge,
    proof:  &'a [Fr],
}

impl Prover {
    pub fn new() -> Self {
        Self {
            sponge: Sponge::new(),
            proof:  Vec::new(),
        }
    }

    pub fn finish(self) -> Vec<Fr> {
        self.proof
    }

    pub fn read(&mut self) -> Fr {
        self.sponge.squeeze()
    }

    pub fn write(&mut self, value: Fr) {
        self.sponge.absorb(value);
        self.proof.push(value);
    }

    fn write_fp(&mut self, value: Fq) {
        // The base field is ever so slightly larger than the scalar field.
        // Assuming uniform random, the probability of overflow is 2^-127.
        let value = value.into_bigint();
        let value = Fr::from_bigint(value).expect("Basefield element exceeds scalarfield.");
        self.write(value);
    }

    pub fn write_g1(&mut self, value: G1Affine) {
        let (x, y) = value.xy().expect("Cannot serialize point at infinity.");
        self.write_fp(*x);
        self.write_fp(*y);
    }

    // Reveal a value to the verifier, but do hash it into the transcript.
    // This is useful for decommitting values.
    pub fn reveal(&mut self, value: Fr) {
        self.proof.push(value);
    }
}

impl<'a> Verifier<'a> {
    pub fn new(proof: &'a [Fr]) -> Self {
        Self {
            sponge: Sponge::new(),
            proof,
        }
    }

    pub fn generate(&mut self) -> Fr {
        self.sponge.squeeze()
    }

    pub fn read(&mut self) -> Fr {
        let value = self.reveal();
        self.sponge.absorb(value);
        value
    }

    pub fn read_fq(&mut self) -> Fq {
        let value = self.read().into_bigint();
        Fq::from_bigint(value).expect("Scalarfield always fits basefield.")
    }

    pub fn read_g1(&mut self) -> G1Affine {
        let x = self.read_fq();
        let y = self.read_fq();
        let g1 = G1Affine::new_unchecked(x, y);
        assert!(g1.is_on_curve());
        assert!(g1.is_in_correct_subgroup_assuming_on_curve());
        g1
    }

    pub fn reveal(&mut self) -> Fr {
        let (value, tail) = self
            .proof
            .split_first()
            .expect("Ran out of proof elements.");
        self.proof = tail;
        *value
    }
}
