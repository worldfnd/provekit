use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, MavrosSchemeData, NoirElement, PublicInputs, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirSchemeData {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
    pub hash_config:            HashConfig,
}

/// Scheme data for the Zinc+ proving backend: the same Noir compilation
/// output as [`NoirSchemeData`], re-tagged to prove with Zinc+ instead of
/// WHIR. The `whir_for_witness` config is retained for the witness solver's
/// domain separator and the `num_challenges` metadata (Zinc+ supports only
/// challenge-free circuits; see [`NoirProofScheme::into_zinc_plus`]).
///
/// A serde newtype, so it is wire-format-identical to `NoirSchemeData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZincPlusSchemeData(pub NoirSchemeData);

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoirProofScheme {
    Noir(NoirSchemeData),
    Mavros(MavrosSchemeData),
    ZincPlus(ZincPlusSchemeData),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub public_inputs:   PublicInputs,
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub fn r1cs(&self) -> &R1CS {
        match self {
            NoirProofScheme::Noir(d) => &d.r1cs,
            NoirProofScheme::Mavros(d) => &d.r1cs,
            NoirProofScheme::ZincPlus(d) => &d.0.r1cs,
        }
    }

    #[must_use]
    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            NoirProofScheme::Noir(d) => &d.whir_for_witness,
            NoirProofScheme::Mavros(d) => &d.whir_for_witness,
            NoirProofScheme::ZincPlus(d) => &d.0.whir_for_witness,
        }
    }

    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        let r1cs = self.r1cs();
        (r1cs.num_constraints(), r1cs.num_witnesses())
    }

    #[must_use]
    pub fn abi(&self) -> &noirc_abi::Abi {
        match self {
            NoirProofScheme::Noir(d) => d.witness_generator.abi(),
            NoirProofScheme::Mavros(d) => &d.abi,
            NoirProofScheme::ZincPlus(d) => d.0.witness_generator.abi(),
        }
    }

    /// Re-tag a compiled Noir scheme to prove with the Zinc+ backend.
    ///
    /// Fails for circuits that require Fiat-Shamir challenges during witness
    /// solving (range checks, lookups, RAM and bin-ops all introduce
    /// challenges) — the Zinc+ backend supports only challenge-free circuits.
    pub fn into_zinc_plus(self) -> anyhow::Result<Self> {
        match self {
            NoirProofScheme::Noir(d) => {
                anyhow::ensure!(
                    d.whir_for_witness.num_challenges == 0
                        && d.split_witness_builders.w2_layers.builders_len() == 0,
                    "the Zinc+ backend supports only challenge-free circuits; this circuit \
                     requires {} Fiat-Shamir challenge(s) (range checks, lookups, RAM and bin-ops \
                     introduce challenges). Use the default WHIR scheme instead.",
                    d.whir_for_witness.num_challenges,
                );
                Ok(NoirProofScheme::ZincPlus(ZincPlusSchemeData(d)))
            }
            other => anyhow::bail!("the Zinc+ scheme requires the Noir compiler, got {other:?}"),
        }
    }
}
