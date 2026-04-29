/// Core Groth16+BSB22 types: Proof, ProvingKey, VerifyingKey.
///
/// Ported from gnark's `backend/groth16/bn254/setup.go` and `prove.go`.
/// Notation follows Figure 4 in the DIZK paper.
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, G2Projective};
use {
    crate::pedersen,
    ark_ec::{pairing::Pairing, AffineRepr},
    ark_ff::Zero,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
};

/// A Groth16+BSB22 proof.
///
/// Contains the standard Groth16 elements (Ar, Bs, Krs) plus
/// BSB22 Pedersen commitments and a batched proof of knowledge.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    /// [A]₁ = Σ wᵢ·[Aᵢ(τ)]₁ + [α]₁ + r·[δ]₁
    pub ar:             G1Affine,
    /// [B]₂ = Σ wᵢ·[Bᵢ(τ)]₂ + [β]₂ + s·[δ]₂
    pub bs:             G2Affine,
    /// [C]₁ = Σ wᵢ·[Kᵢ(τ)]₁ + Σ hⱼ·[Zⱼ(τ)]₁ + s·[A]₁ + r·[B]₁ - rs·[δ]₁
    pub krs:            G1Affine,
    /// Pedersen commitments (BSB22 extension).
    pub commitments:    Vec<G1Affine>,
    /// Batched proof of knowledge for all commitments.
    pub commitment_pok: G1Affine,
}

impl Proof {
    /// Checks that proof elements are on the curve and in the correct subgroup.
    pub fn is_valid(&self) -> bool {
        // Ar must be a non-zero G1 point on the curve.
        // G1 has cofactor 1 on BN254, so on-curve implies in-subgroup.
        if !self.ar.is_on_curve() || self.ar.is_zero() {
            return false;
        }

        // Bs is a G2 point. BN254 G2 has a non-trivial cofactor, so
        // on-curve does NOT imply in-subgroup. Explicit check required.
        if !self.bs.is_on_curve()
            || self.bs.is_zero()
            || !self.bs.is_in_correct_subgroup_assuming_on_curve()
        {
            return false;
        }

        // Krs must be on the curve (zero is technically valid but suspicious).
        if !self.krs.is_on_curve() {
            return false;
        }

        // Commitment points (G1) must be on the curve.
        for c in &self.commitments {
            if !c.is_on_curve() {
                return false;
            }
        }
        if !self.commitment_pok.is_on_curve() {
            return false;
        }

        true
    }
}

/// Groth16 proving key.
///
/// Contains all curve points needed by the prover to generate a proof.
/// These are computed during trusted setup from the toxic waste.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey {
    /// FFT domain cardinality (number of constraints rounded up to power of 2).
    pub domain_size: u64,
    /// Generator of the FFT domain.
    pub domain_gen:  Fr,

    // -- G1 elements --
    /// [α]₁
    pub g1_alpha: G1Affine,
    /// [β]₁
    pub g1_beta:  G1Affine,
    /// [δ]₁
    pub g1_delta: G1Affine,
    /// [Aᵢ(τ)]₁ for each wire (excluding infinity points).
    pub g1_a:     Vec<G1Affine>,
    /// [Bᵢ(τ)]₁ for each wire (excluding infinity points).
    pub g1_b:     Vec<G1Affine>,
    /// [Kᵢ(τ)]₁ for private wires only.
    pub g1_k:     Vec<G1Affine>,
    /// [τⁱ · Z(τ)/δ]₁ for i in 0..domain_size-1.
    pub g1_z:     Vec<G1Affine>,

    // -- G2 elements --
    /// [β]₂
    pub g2_beta:  G2Affine,
    /// [δ]₂
    pub g2_delta: G2Affine,
    /// [Bᵢ(τ)]₂ for each wire (excluding infinity points).
    pub g2_b:     Vec<G2Affine>,

    // -- Infinity tracking --
    /// infinity_a[i] == true means wire i has A(τ) == 0.
    pub infinity_a:    Vec<bool>,
    /// infinity_b[i] == true means wire i has B(τ) == 0.
    pub infinity_b:    Vec<bool>,
    /// Count of infinity points in A.
    pub nb_infinity_a: u64,
    /// Count of infinity points in B.
    pub nb_infinity_b: u64,

    /// Pedersen commitment proving keys (one per BSB22 commitment).
    pub commitment_keys: Vec<pedersen::ProvingKey>,
}

/// Groth16 verifying key.
///
/// Contains the minimal curve points needed by the verifier.
/// Note: precomputed fields (g2_delta_neg, g2_gamma_neg, e_alpha_beta)
/// are not serialized — call `precompute()` after deserialization.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    // -- G1 elements --
    /// [α]₁
    pub g1_alpha: G1Affine,
    /// [Kᵢ(τ)]₁ for public wires (including commitment wires).
    pub g1_k:     Vec<G1Affine>,

    // -- G2 elements --
    /// [β]₂
    pub g2_beta:  G2Affine,
    /// [δ]₂
    pub g2_delta: G2Affine,
    /// [γ]₂
    pub g2_gamma: G2Affine,

    // -- Precomputed (set by precompute(), not serialized) --
    /// -[δ]₂
    pub g2_delta_neg: G2Affine,
    /// -[γ]₂
    pub g2_gamma_neg: G2Affine,
    /// e([α]₁, [β]₂)
    pub e_alpha_beta: <Bn254 as Pairing>::TargetField,

    /// Pedersen commitment verifying keys (one per BSB22 commitment).
    pub commitment_keys:                 Vec<pedersen::VerifyingKey>,
    /// For each commitment, the indices of public/commitment-committed wires.
    pub public_and_commitment_committed: Vec<Vec<usize>>,
    /// Number of challenges derived from each commitment.
    /// Single-challenge: all 1s. Multi-challenge: [N] for one commitment
    /// producing N challenges.
    pub num_challenges_per_commitment:   Vec<usize>,
}

impl CanonicalSerialize for VerifyingKey {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let mut w = writer;
        self.g1_alpha.serialize_with_mode(&mut w, compress)?;
        self.g1_k.serialize_with_mode(&mut w, compress)?;
        self.g2_beta.serialize_with_mode(&mut w, compress)?;
        self.g2_delta.serialize_with_mode(&mut w, compress)?;
        self.g2_gamma.serialize_with_mode(&mut w, compress)?;
        self.commitment_keys.serialize_with_mode(&mut w, compress)?;
        self.public_and_commitment_committed
            .serialize_with_mode(&mut w, compress)?;
        self.num_challenges_per_commitment
            .serialize_with_mode(&mut w, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.g1_alpha.serialized_size(compress)
            + self.g1_k.serialized_size(compress)
            + self.g2_beta.serialized_size(compress)
            + self.g2_delta.serialized_size(compress)
            + self.g2_gamma.serialized_size(compress)
            + self.commitment_keys.serialized_size(compress)
            + self
                .public_and_commitment_committed
                .serialized_size(compress)
            + self.num_challenges_per_commitment.serialized_size(compress)
    }
}

impl ark_serialize::Valid for VerifyingKey {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.g1_alpha.check()?;
        for pt in &self.g1_k {
            pt.check()?;
        }
        self.g2_beta.check()?;
        self.g2_delta.check()?;
        self.g2_gamma.check()?;
        for ck in &self.commitment_keys {
            ck.check()?;
        }
        if self.commitment_keys.len() != self.public_and_commitment_committed.len() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        if self.num_challenges_per_commitment.len() != self.commitment_keys.len() {
            return Err(ark_serialize::SerializationError::InvalidData);
        }
        Ok(())
    }
}

impl CanonicalDeserialize for VerifyingKey {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut r = reader;
        let g1_alpha = G1Affine::deserialize_with_mode(&mut r, compress, validate)?;
        let g1_k = Vec::<G1Affine>::deserialize_with_mode(&mut r, compress, validate)?;
        let g2_beta = G2Affine::deserialize_with_mode(&mut r, compress, validate)?;
        let g2_delta = G2Affine::deserialize_with_mode(&mut r, compress, validate)?;
        let g2_gamma = G2Affine::deserialize_with_mode(&mut r, compress, validate)?;
        let commitment_keys =
            Vec::<pedersen::VerifyingKey>::deserialize_with_mode(&mut r, compress, validate)?;
        let public_and_commitment_committed =
            Vec::<Vec<usize>>::deserialize_with_mode(&mut r, compress, validate)?;
        let num_challenges_per_commitment =
            Vec::<usize>::deserialize_with_mode(&mut r, compress, validate)?;

        Ok(Self {
            g1_alpha,
            g1_k,
            g2_beta,
            g2_delta,
            g2_gamma,
            g2_delta_neg: G2Affine::zero(),
            g2_gamma_neg: G2Affine::zero(),
            e_alpha_beta: ark_ff::AdditiveGroup::ZERO,
            commitment_keys,
            public_and_commitment_committed,
            num_challenges_per_commitment,
        })
    }
}

impl VerifyingKey {
    /// Precompute cached values: e(α,β), -δ₂, -γ₂.
    /// Must be called after deserialization.
    pub fn precompute(&mut self) -> anyhow::Result<()> {
        use ark_ec::pairing::Pairing;
        self.e_alpha_beta = Bn254::pairing(self.g1_alpha, self.g2_beta).0;

        self.g2_delta_neg = (-G2Projective::from(self.g2_delta)).into();

        self.g2_gamma_neg = (-G2Projective::from(self.g2_gamma)).into();

        Ok(())
    }

    /// Number of public witness elements expected (excluding the constant 1
    /// wire).
    pub fn nb_public_witness(&self) -> usize {
        self.g1_k.len() - 1
    }
}

// Serde adapters for ProvingKey.
//
// The proving key is large (hundreds of MB) and arkworks-serialized bytes are
// best read/written outside postcard's wire format to avoid materializing the
// full byte stream in memory. The .pkp file layout treats the PK as an
// out-of-band section appended after the postcard-encoded `Prover` (see
// `provekit_prover::pkp_io`), so the serde impls here are no-ops:
//   * `Serialize` writes `()` (postcard emits zero bytes).
//   * `Deserialize` ignores the input and yields `ProvingKey::empty()`.
//
// In practice these impls only run for `Groth16Prover` round-trips; the file
// I/O layer fills in the real PK after postcard returns.
impl Serialize for ProvingKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Emit a unit value: postcard encodes `()` as zero bytes, leaving the
        // PK out of the postcard stream entirely.
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for ProvingKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _: () = Deserialize::deserialize(deserializer)?;
        Ok(ProvingKey::empty())
    }
}

impl ProvingKey {
    /// A zero-state placeholder used while a `Groth16Prover` is being
    /// reconstituted out of band. The actual proving key is loaded separately
    /// by the .pkp I/O path and replaces this placeholder before any
    /// cryptographic operations occur.
    pub fn empty() -> Self {
        ProvingKey {
            domain_size:     0,
            domain_gen:      Fr::zero(),
            g1_alpha:        G1Affine::zero(),
            g1_beta:         G1Affine::zero(),
            g1_delta:        G1Affine::zero(),
            g1_a:            Vec::new(),
            g1_b:            Vec::new(),
            g1_k:            Vec::new(),
            g1_z:            Vec::new(),
            g2_beta:         G2Affine::zero(),
            g2_delta:        G2Affine::zero(),
            g2_b:            Vec::new(),
            infinity_a:      Vec::new(),
            infinity_b:      Vec::new(),
            nb_infinity_a:   0,
            nb_infinity_b:   0,
            commitment_keys: Vec::new(),
        }
    }
}
