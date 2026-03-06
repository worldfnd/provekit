#[cfg(not(target_arch = "wasm32"))]
use mavros_vm::{ConstraintsLayout, WitnessLayout};
#[cfg(not(target_arch = "wasm32"))]
use noirc_abi::Abi;
use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement, R1CS,
    },
    acir::circuit::Program,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(not(target_arch = "wasm32"))]
pub struct MavrosProver {
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub whir_for_witness:   WhirR1CSScheme,
    pub witgen_binary:      Vec<u64>,
    pub ad_binary:          Vec<u64>,
    pub constraints_layout: ConstraintsLayout,
    pub witness_layout:     WitnessLayout,
    pub hash_config:        HashConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Prover {
    Noir(NoirProver),
    #[cfg(not(target_arch = "wasm32"))]
    Mavros(MavrosProver),
}

impl Prover {
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
            #[cfg(not(target_arch = "wasm32"))]
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
        }
    }

    pub fn size(&self) -> (usize, usize) {
        match self {
            Prover::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
            #[cfg(not(target_arch = "wasm32"))]
            Prover::Mavros(p) => (
                p.constraints_layout.algebraic_size,
                p.witness_layout.algebraic_size,
            ),
        }
    }

    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            Prover::Noir(p) => &p.whir_for_witness,
            #[cfg(not(target_arch = "wasm32"))]
            Prover::Mavros(p) => &p.whir_for_witness,
        }
    }
}

/// Lightweight prover for WASM environments.
///
/// Strips `witness_generator` from [`NoirProver`] since WASM delegates
/// witness generation to `@noir-lang/noir_js`. Pre-computes
/// `num_public_inputs` which is the only value extracted from `program`
/// before it is dropped in the `prove_with_witness` path.
///
/// Embeds the raw compiled-circuit artifact (`circuit_artifact`) so that
/// the `.wpkp` file is fully self-contained — the browser can extract it
/// and pass it to `new Noir(circuitJson)` for witness generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmNoirProver {
    pub hash_config:            HashConfig,
    pub num_public_inputs:      usize,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub whir_for_witness:       WhirR1CSScheme,
    /// Raw bytes of the compiled circuit JSON (output of `nargo compile`).
    /// Passed to `@noir-lang/noir_js` in the browser for witness generation.
    pub circuit_artifact:       Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WasmProver {
    Noir(WasmNoirProver),
}

impl WasmProver {
    /// Create a [`WasmProver`] from a full [`Prover`], embedding the raw
    /// circuit artifact bytes so the `.wpkp` is self-contained.
    pub fn from_prover(prover: Prover, circuit_artifact: Vec<u8>) -> Self {
        match prover {
            Prover::Noir(p) => {
                let num_public_inputs =
                    p.program.functions[0].public_inputs().indices().len();
                WasmProver::Noir(WasmNoirProver {
                    hash_config:            p.hash_config,
                    num_public_inputs,
                    r1cs:                   p.r1cs,
                    split_witness_builders: p.split_witness_builders,
                    whir_for_witness:       p.whir_for_witness,
                    circuit_artifact,
                })
            }
            #[cfg(not(target_arch = "wasm32"))]
            Prover::Mavros(_) => {
                panic!("Mavros prover is not supported in WASM");
            }
        }
    }

    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        match self {
            WasmProver::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
        }
    }

    #[must_use]
    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            WasmProver::Noir(p) => &p.whir_for_witness,
        }
    }

    /// Returns the embedded compiled-circuit artifact bytes.
    #[must_use]
    pub fn circuit_artifact(&self) -> &[u8] {
        match self {
            WasmProver::Noir(p) => &p.circuit_artifact,
        }
    }
}
