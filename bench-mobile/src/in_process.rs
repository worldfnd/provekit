//! Safe in-process helpers for mobile benchmark fixtures.

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::fs;
use {
    anyhow::{Context, Result},
    noirc_abi::{input_parser::Format, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    std::sync::Arc,
};

/// Resident and swapped process memory reported by Linux/Android.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessMemory {
    pub rss_kb:  u64,
    pub swap_kb: u64,
}

/// Read the current Linux/Android process memory counters.
#[must_use]
pub fn process_memory() -> ProcessMemory {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let Ok(status) = fs::read_to_string("/proc/self/status") else {
            return ProcessMemory::default();
        };
        let value = |name: &str| {
            status
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    (key == name).then(|| {
                        value
                            .split_whitespace()
                            .next()
                            .and_then(|value| value.parse().ok())
                            .unwrap_or_default()
                    })
                })
                .unwrap_or_default()
        };
        ProcessMemory {
            rss_kb:  value("VmRSS"),
            swap_kb: value("VmSwap"),
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        ProcessMemory::default()
    }
}

/// Emit a stable raw-log checkpoint for allocator recovery diagnosis.
pub fn log_process_memory(label: &str) -> ProcessMemory {
    let memory = process_memory();
    eprintln!(
        "PROVEKIT_E15_MEMORY phase={label} rss_kb={} swap_kb={}",
        memory.rss_kb, memory.swap_kb
    );
    memory
}

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

/// Prover-only state plus a compressed serialization of its exact matching
/// verifier.
#[derive(Clone)]
pub struct PreparedNoirProverWithSerializedVerifier {
    name:           String,
    prover:         Prover,
    input_map:      InputMap,
    verifier_bytes: Arc<[u8]>,
}

/// Generated proof plus compressed verifier bytes, ready for an out-of-band
/// correctness gate after the measured proof interval.
pub struct ProvedNoirProgramWithSerializedVerifier {
    name:           String,
    proof:          NoirProof,
    verifier_bytes: Arc<[u8]>,
}

/// Compact exact-match proving bundle retained between benchmark iterations.
///
/// This avoids rebuilding the Noir-to-R1CS scheme and recompressing the
/// prover/verifier on every low-memory Android sample.
#[derive(Clone)]
pub struct FrozenNoirProgram {
    name:           String,
    prover_bytes:   Vec<u8>,
    verifier_bytes: Arc<[u8]>,
    input_map:      InputMap,
    input_size:     usize,
}

impl FrozenNoirProgram {
    /// Serialize the exact prepared prover, verifier, and parsed witness input.
    pub fn from_prepared(prepared: PreparedNoirProgram) -> Result<Self> {
        let PreparedNoirProgram {
            name,
            prover,
            verifier,
            input_map,
        } = prepared;
        let prover_bytes = provekit_common::file::serialize(&prover)
            .with_context(|| format!("while freezing {name} benchmark prover"))?;
        let verifier_bytes = provekit_common::file::serialize(&verifier)
            .with_context(|| format!("while freezing {name} benchmark verifier"))?;
        let input_size = postcard::to_stdvec(&input_map)
            .with_context(|| format!("while freezing {name} benchmark input"))?;
        Ok(Self {
            name,
            prover_bytes,
            verifier_bytes: verifier_bytes.into(),
            input_map,
            input_size: input_size.len(),
        })
    }

    /// Hydrate only the prover and witness input for one proof iteration.
    pub fn load_prover_with_serialized_verifier(
        &self,
    ) -> Result<PreparedNoirProverWithSerializedVerifier> {
        let prover = provekit_common::file::deserialize(&self.prover_bytes)
            .with_context(|| format!("while loading frozen {} benchmark prover", self.name))?;
        Ok(PreparedNoirProverWithSerializedVerifier {
            name: self.name.clone(),
            prover,
            input_map: self.input_map.clone(),
            verifier_bytes: self.verifier_bytes.clone(),
        })
    }

    /// Return exact payload sizes without serializing expanded proving state.
    #[must_use]
    pub fn proving_payload_sizes(&self) -> (usize, usize) {
        (self.prover_bytes.len(), self.input_size)
    }
}

impl PreparedNoirProver {
    /// Return the exact serialized PKP and witness-input payload sizes used by
    /// the proof-only benchmark.
    pub fn proving_payload_sizes(&self) -> Result<(usize, usize)> {
        let prover = provekit_common::file::serialize(&self.prover)
            .with_context(|| format!("while serializing {} benchmark prover", self.name))?;
        let input = postcard::to_stdvec(&self.input_map)
            .with_context(|| format!("while serializing {} benchmark input", self.name))?;
        Ok((prover.len(), input.len()))
    }

    /// Generate a proof from state already stripped of verifier allocations.
    pub fn prove(self) -> Result<NoirProof> {
        self.prover
            .prove(self.input_map)
            .with_context(|| format!("while proving {} benchmark fixture", self.name))
    }
}

impl PreparedNoirProverWithSerializedVerifier {
    /// Return the exact PKP and witness-input sizes; verifier bytes are not a
    /// proving input and are deliberately excluded.
    pub fn proving_payload_sizes(&self) -> Result<(usize, usize)> {
        let prover = provekit_common::file::serialize(&self.prover)
            .with_context(|| format!("while serializing {} benchmark prover", self.name))?;
        let input = postcard::to_stdvec(&self.input_map)
            .with_context(|| format!("while serializing {} benchmark input", self.name))?;
        Ok((prover.len(), input.len()))
    }

    /// Generate a proof without retaining the expanded verifier in memory.
    pub fn prove(self) -> Result<ProvedNoirProgramWithSerializedVerifier> {
        let proof = self
            .prover
            .prove(self.input_map)
            .with_context(|| format!("while proving {} benchmark fixture", self.name))?;
        Ok(ProvedNoirProgramWithSerializedVerifier {
            name: self.name,
            proof,
            verifier_bytes: self.verifier_bytes,
        })
    }
}

impl ProvedNoirProgramWithSerializedVerifier {
    /// Return the generated proof for exact serialized-size accounting.
    pub fn proof(&self) -> &NoirProof {
        &self.proof
    }

    /// Rehydrate the exact matching verifier, accept the valid proof, and
    /// reject a transcript mutation outside the measured proof interval.
    pub fn verify_and_reject_tampered(self) -> Result<()> {
        log_process_memory("before_verifier_hydration");
        let mut verifier: Verifier =
            provekit_common::file::deserialize(self.verifier_bytes.as_ref())
                .with_context(|| format!("while deserializing {} benchmark verifier", self.name))?;
        log_process_memory("after_verifier_hydration");
        verifier
            .verify(&self.proof)
            .with_context(|| format!("while verifying {} benchmark proof", self.name))?;

        let mut tampered = self.proof;
        let byte = tampered
            .whir_r1cs_proof
            .narg_string
            .first_mut()
            .context("proof transcript must not be empty")?;
        *byte ^= 1;
        anyhow::ensure!(
            verifier.verify(&tampered).is_err(),
            "tampered {} benchmark proof was accepted",
            self.name
        );
        log_process_memory("after_verification_gate");
        Ok(())
    }
}

impl PreparedNoirProgram {
    /// Return the exact serialized PKP and witness-input payload sizes used by
    /// a benchmark that retains its matching verifier for the correctness gate.
    pub fn proving_payload_sizes(&self) -> Result<(usize, usize)> {
        let prover = provekit_common::file::serialize(&self.prover)
            .with_context(|| format!("while serializing {} benchmark prover", self.name))?;
        let input = postcard::to_stdvec(&self.input_map)
            .with_context(|| format!("while serializing {} benchmark input", self.name))?;
        Ok((prover.len(), input.len()))
    }

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

    /// Serialize the exact matching verifier, then drop its expanded state
    /// before the memory-constrained proof begins.
    pub fn into_prover_with_serialized_verifier(
        self,
    ) -> Result<PreparedNoirProverWithSerializedVerifier> {
        let Self {
            name,
            prover,
            verifier,
            input_map,
        } = self;
        let verifier_bytes = provekit_common::file::serialize(&verifier)
            .with_context(|| format!("while serializing {name} benchmark verifier"))?
            .into();
        drop(verifier);
        Ok(PreparedNoirProverWithSerializedVerifier {
            name,
            prover,
            input_map,
            verifier_bytes,
        })
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
    /// Return the generated proof for exact serialized-size accounting.
    pub fn proof(&self) -> &NoirProof {
        &self.proof
    }

    /// Verify proof matching verifier state.
    pub fn verify(mut self) -> Result<Self> {
        self.verifier
            .verify(&self.proof)
            .with_context(|| format!("while verifying {} benchmark fixture", self.name))?;

        Ok(self)
    }

    /// Verify the valid proof and require rejection after mutating its
    /// transcript. This is a correctness gate and must run outside measured
    /// samples.
    pub fn verify_and_reject_tampered(mut self) -> Result<()> {
        self.verifier
            .verify(&self.proof)
            .with_context(|| format!("while verifying {} validation canary", self.name))?;

        let mut tampered = self.proof.clone();
        let byte = tampered
            .whir_r1cs_proof
            .narg_string
            .first_mut()
            .context("proof transcript must not be empty")?;
        *byte ^= 1;

        anyhow::ensure!(
            self.verifier.verify(&tampered).is_err(),
            "tampered {} validation canary was accepted",
            self.name
        );
        Ok(())
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

/// Verify a proof directly from its Noir artifact and reject a transcript
/// mutation without constructing or retaining a prover.
pub fn verify_noir_proof_from_json(
    name: &str,
    program_json: &str,
    proof: &NoirProof,
) -> Result<()> {
    let program: ProgramArtifact = serde_json::from_str(program_json)
        .with_context(|| format!("while deserializing {name} verifier artifact"))?;
    let scheme = NoirProofScheme::from_program(program)
        .with_context(|| format!("while preparing {name} verifier scheme"))?;
    let mut verifier = Verifier::from_noir_proof_scheme(scheme);
    verifier
        .verify(proof)
        .with_context(|| format!("while verifying {name} benchmark proof"))?;

    let mut tampered = proof.clone();
    let byte = tampered
        .whir_r1cs_proof
        .narg_string
        .first_mut()
        .context("proof transcript must not be empty")?;
    *byte ^= 1;
    anyhow::ensure!(
        verifier.verify(&tampered).is_err(),
        "tampered {name} benchmark proof was accepted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::process_memory;

    #[test]
    fn process_memory_reader_is_safe_on_every_host() {
        let _memory = process_memory();
        #[cfg(target_os = "linux")]
        assert!(_memory.rss_kb > 0);
    }
}
