use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, MavrosProver, NoirElement, R1CS,
    },
    acir::circuit::Program,
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProver {
    pub hash_config:            HashConfig,
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

/// Prover data for the Zinc+ backend: identical payload to [`NoirProver`]
/// (same Noir compilation output), re-tagged to prove with Zinc+. A serde
/// newtype, so it is wire-format-identical to `NoirProver`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZincPlusProver(pub NoirProver);

/// On-disk **ProveKit Prover** (PKP) — the prover-side scheme that gets
/// serialized to a `.pkp` file by `prepare` and loaded by `prove`.
///
/// Holds the R1CS, witness builders, WHIR config, and frontend-specific
/// program data needed to produce a proof.
///
/// INVARIANT: Variant order is wire-format-critical (postcard uses positional
/// discriminants). Do not reorder, cfg-gate, or insert variants without
/// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Prover {
    Noir(NoirProver),
    Mavros(MavrosProver),
    ZincPlus(ZincPlusProver),
}

impl Prover {
    /// Convert a compilation output into the on-disk prover format.
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Prover::Noir(NoirProver {
                hash_config:            d.hash_config,
                program:                d.program,
                r1cs:                   d.r1cs,
                split_witness_builders: d.split_witness_builders,
                witness_generator:      d.witness_generator,
                whir_for_witness:       d.whir_for_witness,
            }),
            NoirProofScheme::Mavros(d) => Prover::Mavros(MavrosProver {
                abi:                d.abi,
                num_public_inputs:  d.num_public_inputs,
                whir_for_witness:   d.whir_for_witness,
                witgen_binary:      d.witgen_binary,
                ad_binary:          d.ad_binary,
                constraints_layout: d.constraints_layout,
                witness_layout:     d.witness_layout,
                hash_config:        d.hash_config,
            }),
            NoirProofScheme::ZincPlus(d) => Prover::ZincPlus(ZincPlusProver(NoirProver {
                hash_config:            d.0.hash_config,
                program:                d.0.program,
                r1cs:                   d.0.r1cs,
                split_witness_builders: d.0.split_witness_builders,
                witness_generator:      d.0.witness_generator,
                whir_for_witness:       d.0.whir_for_witness,
            })),
        }
    }

    pub fn abi(&self) -> &Abi {
        match self {
            Prover::Noir(p) => p.witness_generator.abi(),
            Prover::Mavros(p) => &p.abi,
            Prover::ZincPlus(p) => p.0.witness_generator.abi(),
        }
    }

    pub fn size(&self) -> (usize, usize) {
        match self {
            Prover::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
            Prover::Mavros(p) => (p.constraints_layout.size(), p.witness_layout.size()),
            Prover::ZincPlus(p) => (p.0.r1cs.num_constraints(), p.0.r1cs.num_witnesses()),
        }
    }

    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            Prover::Noir(p) => &p.whir_for_witness,
            Prover::Mavros(p) => &p.whir_for_witness,
            Prover::ZincPlus(p) => &p.0.whir_for_witness,
        }
    }
}
