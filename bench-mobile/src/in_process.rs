//! Safe in-process helpers built on the same ProveKit implementation as the C
//! FFI entrypoints.

use {
    anyhow::{Context, Result},
    noirc_abi::{input_parser::Format, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    provekit_backend_bn254::{Bn254Field, Prove, ProvekitProof, Prover, Verifier, Verify},
    provekit_common::HashConfig,
    provekit_r1cs_compiler::NoirCompiler,
};

/// BN254 proof produced by the mobile benchmark fixtures.
pub type NoirProof = ProvekitProof<Bn254Field>;

/// Ask the platform allocator to return free pages to the OS after a large
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

        // SAFETY: malloc_trim does not take ownership of Rust allocations. It
        // only asks the process allocator to release unused free-list pages.
        malloc_trim(0);
    }
}

/// Prepared proving and verification state for one Noir benchmark program.
#[derive(Clone)]
pub struct PreparedNoirProgram {
    name:      String,
    prover:    Prover,
    verifier:  Verifier,
    input_map: InputMap,
}

impl PreparedNoirProgram {
    /// Return the R1CS size exposed by the prepared prover.
    pub fn prover_size(&self) -> (usize, usize) {
        self.prover.size()
    }

    /// Return the number of R1CS constraints in the prepared verifier.
    pub fn constraint_count(&self) -> usize {
        self.verifier.r1cs.num_constraints()
    }

    /// Return the number of parsed ABI input values.
    pub fn input_count(&self) -> usize {
        self.input_map.len()
    }

    /// Generate and bind a proof to the matching verifier state.
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

    /// Generate only the proof, dropping verifier-side state before proving.
    pub fn prove_only(self) -> Result<NoirProof> {
        let Self {
            name,
            prover,
            verifier,
            input_map,
        } = self;

        drop(verifier);
        trim_process_memory();

        prover
            .prove(input_map)
            .with_context(|| format!("while proving {name} benchmark fixture"))
    }
}

/// Verified-ready proof plus verifier state for one Noir benchmark program.
#[derive(Clone)]
pub struct VerifiedNoirProgram {
    name:     String,
    verifier: Verifier,
    proof:    NoirProof,
}

impl VerifiedNoirProgram {
    /// Verify the proof against its matching verifier state.
    pub fn verify(mut self) -> Result<Self> {
        self.verifier
            .verify(&self.proof)
            .with_context(|| format!("while verifying {} benchmark fixture", self.name))?;

        Ok(self)
    }
}

/// Prepare a Noir program from an already-compiled artifact JSON string and a
/// TOML witness input string.
pub fn prepare_noir_program_from_json(
    name: impl Into<String>,
    program_json: &str,
    prover_toml: &str,
) -> Result<PreparedNoirProgram> {
    let name = name.into();
    let program: ProgramArtifact = serde_json::from_str(program_json)
        .with_context(|| format!("while deserializing {name} program artifact"))?;
    let scheme = NoirCompiler::from_program(program, HashConfig::default())
        .with_context(|| format!("while preparing {name} noir proof scheme"))?;
    let input_map = Format::Toml
        .parse(prover_toml, scheme.abi())
        .with_context(|| format!("while parsing {name} prover inputs"))?;

    Ok(PreparedNoirProgram {
        name,
        prover: Prover::from_noir_proof_scheme(scheme.clone()),
        verifier: Verifier::from_noir_proof_scheme(scheme),
        input_map,
    })
}
