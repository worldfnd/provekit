use {
    crate::{Prover, Verifier},
    ark_bn254::{Fr, G1Affine, G1Projective},
    ark_ec::VariableBaseMSM,
    rand::{Rng, SeedableRng},
    rand_chacha::ChaCha20Rng,
    thiserror::Error,
};

const SEED: [u8; 32] = *b"pedersen::PedersenCommitter::new";

// TODO: Better and completer error handling
pub struct PedersenCommitter {
    // Generators h, g_1, g_2, ..., g_n for the Pedersen commitment scheme.
    generators: Vec<G1Affine>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Pedersen commitment failed to verify.")]
    PedersenVerificationFailed,
    #[error("Pedersen commitment equality proof failed to verify.")]
    PedersenEqualityVerificationFailed,
}

impl PedersenCommitter {
    pub fn new(size: usize) -> Self {
        // Generators are PRNG generated.
        // IDEA: We coould append more values as we need them.
        let mut rng = ChaCha20Rng::from_seed(SEED);
        Self {
            generators: (0..=size).map(|_| rng.gen()).collect(),
        }
    }

    /// Commit to a value using the Pedersen commitment scheme.
    /// Returns the prover secret and the commitment.
    /// IDEA: Prover never uses the G1Affine, so we may as well write it to
    /// transcript?
    pub fn commit(&self, rng: &mut impl Rng, values: &[Fr]) -> (Fr, G1Affine) {
        let secret = rng.gen();
        (secret, self.compute_commitment(secret, values))
    }

    pub fn compute_commitment(&self, secret: Fr, values: &[Fr]) -> G1Affine {
        assert!(
            values.len() < self.generators.len(),
            "Too many values for the generators."
        );
        let mut commitment = self.generators[0] * secret;
        commitment += G1Projective::msm_unchecked(&self.generators[1..], values);
        commitment.into()
    }

    /// Batch commitment as in Hyrax.
    pub fn batch_commit(
        &self,
        rng: &mut impl Rng,
        transcript: &mut Prover,
        values: &[Fr],
    ) -> Vec<Fr> {
        assert!(
            values.len() % (self.generators.len() - 1) == 0,
            "Values not whole number of vectors."
        );
        // This uses Pipenger, but for Hyrax we could also do WNAF over the columns.
        // Benchmarking shows that take about equal time.
        // TODO: there should be a way to combine both.
        values
            .chunks_exact(self.generators.len() - 1)
            .map(|chunk| {
                let (s, c) = self.commit(rng, chunk);
                transcript.write_g1(c);
                s
            })
            .collect()
    }

    pub fn verify(&self, commitment: G1Affine, secret: Fr, values: &[Fr]) -> Result<(), Error> {
        if commitment == self.compute_commitment(secret, values) {
            Ok(())
        } else {
            Err(Error::PedersenVerificationFailed)
        }
    }

    // Prove that two values are equal.
    // Only the secrets are required.
    // **Warning** This does not verify the vector lentghs and they are implicitely
    // zero padded.
    pub fn prove_equal(&self, rng: &mut impl Rng, transcript: &mut Prover, a: Fr, b: Fr) {
        let (s, c) = self.commit(rng, &[]);
        transcript.write_g1(c);
        let r = transcript.read();
        let z = r * (a - b) + s;
        transcript.write(z);
    }

    pub fn verify_equal(
        &self,
        transcript: &mut Verifier,
        a: G1Affine,
        b: G1Affine,
    ) -> Result<(), Error> {
        let c = transcript.read_g1();
        let r = transcript.generate();
        let z = transcript.read();
        let left = self.generators[0] * z;
        let right = (a - b) * r + c;
        if left == right {
            Ok(())
        } else {
            Err(Error::PedersenEqualityVerificationFailed)
        }
    }

    pub fn prove_product(
        &self,
        rng: &mut impl Rng,
        transcript: &mut Prover,
        a: (Fr, G1Affine, Fr),
        b: (Fr, Fr),
        c: Fr,
    ) {
        let (u, v) = rng.gen();
        let (su, cu) = self.commit(rng, &[u]);
        let (sv, cv) = self.commit(rng, &[v]);
        transcript.write_g1(cu);
        transcript.write_g1(cv);
        let sw = rng.gen::<Fr>();
        let cw = self.generators[0] * sw + a.1 * v;
        transcript.write_g1(cw.into());
        let r = transcript.read();
        transcript.write(su + r * a.0);
        transcript.write(u + r * a.2);
        transcript.write(sv + r * b.0);
        transcript.write(v + r * b.1);
        transcript.write(sw + r * (c - a.0 * b.1));
    }

    pub fn verify_product(
        &self,
        transcript: &mut Verifier,
        ca: G1Affine,
        cb: G1Affine,
        cc: G1Affine,
    ) -> Result<(), Error> {
        let (h, g) = (self.generators[0], self.generators[1]);
        let cu = transcript.read_g1();
        let cv = transcript.read_g1();
        let cw = transcript.read_g1();
        let r = transcript.generate();
        let zsa = transcript.read();
        let za = transcript.read();
        let zsb = transcript.read();
        let zb = transcript.read();
        let z = transcript.read();
        if cu + ca * r != h * zsa + g * za {
            return Err(Error::PedersenVerificationFailed);
        }
        if cv + cb * r != h * zsb + g * zb {
            return Err(Error::PedersenVerificationFailed);
        }
        if cw + cc * r != h * z + ca * zb {
            return Err(Error::PedersenVerificationFailed);
        }
        Ok(())
    }

    /// Proof that c = a . b.
    /// From a only the secret and values are used, from b nothing is used, and
    /// from c only the secret is used.
    pub fn prove_dot_product(
        &self,
        rng: &mut impl Rng,
        transcript: &mut Prover,
        a: (Fr, &[Fr]),
        b: &[Fr],
        c: Fr,
    ) {
        let secret: Vec<Fr> = (0..a.1.len()).map(|_| rng.gen()).collect();
        let secret_dot = secret.iter().zip(b.iter()).map(|(s, b)| s * b).sum();
        let (s_u, u) = self.commit(rng, &secret);
        let (s_v, v) = self.commit(rng, &[secret_dot]);
        transcript.write_g1(u);
        transcript.write_g1(v);
        let r = transcript.read();
        transcript.write(s_u + r * a.0);
        transcript.write(s_v + r * c);
        secret.into_iter().zip(a.1.iter()).for_each(|(s, a)| {
            transcript.write(s + r * a);
        });
    }

    // Verify that c = a . b.
    pub fn verify_dot_product(
        &self,
        transcript: &mut Verifier,
        a: G1Affine,
        b: &[Fr],
        c: G1Affine,
    ) -> Result<(), Error> {
        let u = transcript.read_g1();
        let v = transcript.read_g1();
        let r = transcript.generate();
        let z_u = transcript.read();
        let z_v = transcript.read();
        let z: Vec<Fr> = (0..b.len()).map(|_| transcript.read()).collect();
        if u + a * r != self.compute_commitment(z_u, &z) {
            return Err(Error::PedersenVerificationFailed);
        }
        let secret_dot = z.iter().zip(b.iter()).map(|(z, b)| z * b).sum();
        let lhs = v + c * r;
        let rhs = self.compute_commitment(z_v, &[secret_dot]);
        if lhs != rhs {
            return Err(Error::PedersenVerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // TODO: Randomized testing

    #[test]
    fn test_commit() {
        let size = 1000;
        let mut rng = ChaCha20Rng::from_entropy();
        let pedersen = PedersenCommitter::new(size);
        let a = (0..size).map(|_| rng.gen()).collect::<Vec<Fr>>();

        // Prove
        let (s, c) = pedersen.commit(&mut rng, &a);

        // Verify
        pedersen.verify(c, s, &a).unwrap();
    }

    #[test]
    fn test_equal() {
        let size = 1000;
        let mut rng = ChaCha20Rng::from_entropy();
        let pedersen = PedersenCommitter::new(size);
        let a = (0..size).map(|_| rng.gen()).collect::<Vec<Fr>>();

        // Prove
        let mut transcript = Prover::new();
        let (sa, ca) = pedersen.commit(&mut rng, &a);
        transcript.write_g1(ca);
        let (sb, cb) = pedersen.commit(&mut rng, &a);
        transcript.write_g1(cb);
        pedersen.prove_equal(&mut rng, &mut transcript, sa, sb);
        let proof = transcript.finish();
        dbg!(proof.len() * std::mem::size_of::<Fr>());

        // Verify
        let mut transcript = Verifier::new(&proof);
        let ca = transcript.read_g1();
        let cb = transcript.read_g1();
        pedersen.verify_equal(&mut transcript, ca, cb).unwrap();
    }

    #[test]
    fn test_product() {
        let mut rng = ChaCha20Rng::from_entropy();
        let pedersen = PedersenCommitter::new(1);
        let a = rng.gen();
        let b = rng.gen();
        let c = a * b;

        // Prove
        let mut transcript = Prover::new();
        let (sa, ca) = pedersen.commit(&mut rng, &[a]);
        let (sb, cb) = pedersen.commit(&mut rng, &[b]);
        let (sc, cc) = pedersen.commit(&mut rng, &[c]);
        transcript.write_g1(ca);
        transcript.write_g1(cb);
        transcript.write_g1(cc);
        pedersen.prove_product(&mut rng, &mut transcript, (sa, ca, a), (sb, b), sc);
        let proof = transcript.finish();
        dbg!(proof.len() * std::mem::size_of::<Fr>());

        // Verify
        let mut transcript = Verifier::new(&proof);
        let ca = transcript.read_g1();
        let cb = transcript.read_g1();
        let cc = transcript.read_g1();
        pedersen
            .verify_product(&mut transcript, ca, cb, cc)
            .unwrap();
    }

    #[test]
    fn test_dot() {
        let size = 100;
        let mut rng = ChaCha20Rng::from_entropy();
        let pedersen = PedersenCommitter::new(size);
        let a = (0..size).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let b = (0..size).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).sum();

        // Prove
        let mut transcript = Prover::new();
        let (sa, ca) = pedersen.commit(&mut rng, &a);
        transcript.write_g1(ca);
        let (sc, cc) = pedersen.commit(&mut rng, &[c]);
        transcript.write_g1(cc);
        pedersen.prove_dot_product(&mut rng, &mut transcript, (sa, &a), &b, sc);
        let proof = transcript.finish();
        dbg!(proof.len() * std::mem::size_of::<Fr>());

        // Verify
        let mut transcript = Verifier::new(&proof);
        let ca = transcript.read_g1();
        let cc = transcript.read_g1();
        pedersen
            .verify_dot_product(&mut transcript, ca, &b, cc)
            .unwrap();
    }
}
