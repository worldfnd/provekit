//! Safe in-process helpers for mobile benchmark fixtures.

use {
    anyhow::{Context, Result},
    noirc_abi::{input_parser::Format, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
};

/// Ask platform allocator return free pages OS large
/// proof allocation burst.
pub fn trim_process_memory() {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    unsafe {
        type MallocTrim = unsafe extern "C" fn(libc::size_t) -> libc::c_int;

        let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"malloc_trim".as_ptr().cast());
        if symbol.is_null() {
            return;
        }
        let malloc_trim: MallocTrim = std::mem::transmute(symbol);

        // SAFETY: malloc_trim does not take ownership Rust allocations. It
        // only asks process allocator release unused free-list pages.
        malloc_trim(0);
    }
}

/// Prepared proving verification state one Noir benchmark program.
#[derive(Clone)]
pub struct PreparedNoirProgram {
    name:      String,
    prover:    Prover,
    verifier:  Verifier,
    input_map: InputMap,
}

/// Prover-only state prepared before a measured proof iteration.
#[derive(Clone)]
pub struct PreparedNoirProver {
    name:      String,
    prover:    Prover,
    input_map: InputMap,
}

impl PreparedNoirProver {
    /// Generate a proof from state already stripped of verifier allocations.
    pub fn prove(self) -> Result<NoirProof> {
        self.prover
            .prove(self.input_map)
            .with_context(|| format!("while proving {} benchmark fixture", self.name))
    }
}

impl PreparedNoirProgram {
    /// Return R1CS size exposed by prepared prover.
    pub fn prover_size(&self) -> (usize, usize) {
        self.prover.size()
    }

    /// Return number R1CS constraints in prepared verifier.
    pub fn constraint_count(&self) -> usize {
        self.verifier.r1cs.num_constraints()
    }

    /// Return number parsed ABI input values.
    pub fn input_count(&self) -> usize {
        self.input_map.len()
    }

    /// Generate bind proof matching verifier state.
    pub fn prove(self) -> Result<VerifiedNoirProgram> {
        let proof = self
            .prover
            .prove(self.input_map)
            .with_context(|| format!("while proving {} benchmark fixture", self.name))?;

        Ok(VerifiedNoirProgram {
            name: self.name,
            verifier: self.verifier,
            proof,
        })
    }

    /// Generate only proof, dropping verifier-side state before proving.
    pub fn prove_only(self) -> Result<NoirProof> {
        self.into_prover_only().prove()
    }

    /// Drop verifier-side state before entering a measured proof iteration.
    pub fn into_prover_only(self) -> PreparedNoirProver {
        let Self {
            name,
            prover,
            verifier,
            input_map,
        } = self;

        drop(verifier);
        PreparedNoirProver {
            name,
            prover,
            input_map,
        }
    }
}

/// Verified-ready proof plus verifier state one Noir benchmark program.
#[derive(Clone)]
pub struct VerifiedNoirProgram {
    name:     String,
    verifier: Verifier,
    proof:    NoirProof,
}

impl VerifiedNoirProgram {
    /// Verify proof matching verifier state.
    pub fn verify(mut self) -> Result<Self> {
        self.verifier
            .verify(&self.proof)
            .with_context(|| format!("while verifying {} benchmark fixture", self.name))?;

        Ok(self)
    }
}

/// Prepare Noir already-compiled artifact JSON string and
/// TOML witness input string.
pub fn prepare_noir_program_from_json(
    name: impl Into<String>,
    program_json: &str,
    prover_toml: &str,
) -> Result<PreparedNoirProgram> {
    let name = name.into();
    let program: ProgramArtifact = serde_json::from_str(program_json)
        .with_context(|| format!("while deserializing {name} program artifact"))?;
    let scheme = NoirProofScheme::from_program(program)
        .with_context(|| format!("while preparing {name} noir proof scheme"))?;
    let input_map = Format::Toml
        .parse(prover_toml, &scheme.witness_generator.abi)
        .with_context(|| format!("while parsing {name} prover inputs"))?;

    Ok(PreparedNoirProgram {
        name,
        prover: Prover::from_noir_proof_scheme(scheme.clone()),
        verifier: Verifier::from_noir_proof_scheme(scheme),
        input_map,
    })
}
