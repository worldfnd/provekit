use {
    super::Command,
    anyhow::{Context as _, Result},
    argh::FromArgs,
    ark_ff::{BigInteger, PrimeField},
    noirc_abi::AbiVisibility,
    provekit_common::{file::read, FieldElement, HashConfig, NoirProofScheme, Verifier, R1CS},
    provekit_groth16::CommitmentInfo,
    provekit_r1cs_compiler::NoirCompiler,
    serde::Serialize,
    std::{
        fs::File,
        io::{BufWriter, Write},
        path::PathBuf,
        str::FromStr,
    },
    tracing::{info, instrument},
};

/// Export a Noir program's R1CS to JSON for the gnark trusted-setup
/// importer.
///
/// The output JSON matches the schema consumed by
/// `trusted-setup/cmd/import_r1cs/main.go`. The downstream pipeline is:
/// this exporter writes JSON; `import_r1cs` converts it to a gnark `.r1cs`
/// binary; the trusted-setup CLI runs Phase 2 against it; the resulting
/// `pk`/`vk` are imported back via `gnark_import` and consumed by
/// `prepare --groth16-pk-in/--groth16-vk-in`.
///
/// Commitments (BSB22 / Pedersen): Provekit has one real Pedersen
/// commitment from which N challenges are derived via `hash_to_fr_multi`;
/// gnark's setup allocates exactly one `vk.G1.K` slot per registered
/// commitment. To get the N K-base slots Provekit's verifier needs, we
/// emit N entries: entry [0] is the real commitment carrying the full
/// `private_committed` list, entries [1..N] are dummies with empty
/// `private_committed` (zero Pedersen storage cost) whose only purpose is
/// the K-base allocation. `gnark_import.rs` truncates the dummies away
/// before `setup_from_ceremony` validates shapes — the protocol layer
/// (prover + verifier) only ever touches `commitment_keys[0]`.
///
/// Only available in `program_path` mode (the compiled scheme carries
/// `whir_for_witness`); `--pkv` mode emits no commitments because
/// `Verifier` does not persist commitment metadata.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "export-gnark-r1cs")]
pub struct Args {
    /// path to a Noir ProgramArtifact JSON (`target/<circuit>.json`).
    /// Mutually exclusive with --pkv. Use --pkv when convenient — it
    /// avoids any Noir-version skew between this CLI and the compiled
    /// artifact.
    #[argh(positional)]
    program_path: Option<PathBuf>,

    /// path to an existing `.pkv` (Provekit Verifier) file. Pulls the
    /// R1CS directly from the already-compiled scheme — guarantees the
    /// exported R1CS matches exactly what `prepare` produced.
    #[argh(option, long = "pkv")]
    pkv: Option<PathBuf>,

    /// output JSON path (default: circuit.r1cs.json in the current dir)
    #[argh(option, long = "out", short = 'o')]
    out: Option<PathBuf>,

    /// hash algorithm — only used in the Noir-compile path. Matches
    /// `prepare`'s default. Ignored when --pkv is set.
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,
}

#[derive(Serialize)]
struct R1CSDump {
    num_public_inputs: usize,
    num_witnesses:     usize,
    num_constraints:   usize,
    constraints:       Vec<ConstraintRow>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    commitments:       Vec<CommitmentDump>,
}

/// Mirrors gnark's `constraint.Groth16Commitment` so the Go importer can
/// register it via `system.AddCommitment` byte-for-byte. See the schema in
/// `cmd/import_r1cs/main.go::rawCommit`.
#[derive(Serialize)]
struct CommitmentDump {
    public_and_commitment_committed: Vec<usize>,
    private_committed:               Vec<usize>,
    nb_public_committed:             usize,
    /// `CommitmentIndex` in gnark's struct: the wire gnark treats as the
    /// holder of this commitment's value. Each emitted commitment uses a
    /// distinct sorted challenge wire so gnark allocates one K-base per.
    commitment_wire:                 usize,
}

#[derive(Serialize)]
struct ConstraintRow {
    a: Vec<Term>,
    b: Vec<Term>,
    c: Vec<Term>,
}

/// A single sparse term `(wire_id, coefficient)`. Serialized as a 2-element
/// JSON array so the file stays compact for million-constraint circuits.
#[derive(Serialize)]
struct Term(usize, String);

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let (r1cs, commitments) = match (&self.pkv, &self.program_path) {
            (Some(pkv_path), None) => {
                info!(path = %pkv_path.display(), "loading R1CS from existing .pkv");
                let verifier: Verifier =
                    read(pkv_path).with_context(|| format!("reading {}", pkv_path.display()))?;
                // Verifier does not persist commitment metadata for the
                // Groth16 backend (see prepare.rs where `whir_for_witness`
                // is set to None). Emit zero commitments — user must use
                // `program_path` mode for circuits with BSB22 commitments.
                (verifier.r1cs, Vec::new())
            }
            (None, Some(program_path)) => {
                info!(path = %program_path.display(), "compiling Noir program");
                let hash_config =
                    HashConfig::from_str(&self.hash).map_err(|e| anyhow::anyhow!("{}", e))?;
                let scheme = NoirCompiler::from_file(program_path, hash_config)
                    .context("while compiling Noir program")?;
                let NoirProofScheme::Noir(d) = scheme else {
                    anyhow::bail!("export-gnark-r1cs only supports Noir-compiled schemes");
                };
                let mut r1cs = d.r1cs;
                let abi = d.witness_generator.abi;
                let w1_size = d.whir_for_witness.w1_size;
                let challenge_offsets = d.whir_for_witness.challenge_offsets.clone();

                // Same derivation `prepare.rs` uses to compute
                // `r1cs.num_public_inputs` from the Noir ABI (count public
                // parameters, then add the return type's field count if it's
                // marked public). The Noir compiler doesn't set
                // `num_public_inputs` on the R1CS (WHIR tracks public inputs
                // separately); for Groth16 / ceremony purposes we must
                // classify wires as public vs private.
                let mut n_public: usize = abi
                    .parameters
                    .iter()
                    .filter(|p| p.is_public())
                    .map(|p| p.typ.field_count() as usize)
                    .sum();
                if let Some(ret) = &abi.return_type {
                    if matches!(ret.visibility, AbiVisibility::Public) {
                        n_public += ret.abi_type.field_count() as usize;
                    }
                }
                r1cs.num_public_inputs = n_public;

                // Emit the N-dummy commitment layout described in the
                // function-level docs. Entry [0] is the real commitment with
                // the full `private_committed` list; entries [1..N] are
                // dummies with empty `private_committed` carrying just a
                // `commitment_wire`. Entries must appear in ascending
                // `commitment_wire` order — gnark Phase 2 matches by exact
                // next-index (`phase2.go:289`) — which is already true
                // because `sorted_challenges` is sorted by construction.
                let commitments = if !challenge_offsets.is_empty() {
                    let num_public = 1 + r1cs.num_public_inputs;
                    let private_w1_wires: Vec<usize> = (num_public..w1_size).collect();
                    if private_w1_wires.is_empty() {
                        Vec::new()
                    } else {
                        let public_committed: Vec<usize> = (1..num_public).collect();
                        let mut sorted_challenges: Vec<usize> = challenge_offsets
                            .iter()
                            .map(|&offset| w1_size + offset)
                            .collect();
                        sorted_challenges.sort_unstable();
                        let mut pub_and_commitment = public_committed;
                        let nb_public_committed = pub_and_commitment.len();
                        // gnark's `PublicAndCommitmentCommitted` is "sorted
                        // list of ids of public AND commitment-committed
                        // wires". Our commitments commit no other
                        // commitments, so this is just the public list.
                        pub_and_commitment.sort_unstable();

                        let mut out = Vec::with_capacity(sorted_challenges.len());
                        // Entry [0]: real commitment, full PrivateCommitted.
                        out.push(CommitmentDump {
                            public_and_commitment_committed: pub_and_commitment.clone(),
                            private_committed: private_w1_wires,
                            nb_public_committed,
                            commitment_wire: sorted_challenges[0],
                        });
                        // Entries [1..N]: dummies — empty PrivateCommitted,
                        // each contributing one K-base slot for the
                        // corresponding challenge wire.
                        for &chal_wire in &sorted_challenges[1..] {
                            out.push(CommitmentDump {
                                public_and_commitment_committed: pub_and_commitment.clone(),
                                private_committed: Vec::new(),
                                nb_public_committed,
                                commitment_wire: chal_wire,
                            });
                        }
                        out
                    }
                } else {
                    Vec::new()
                };

                (r1cs, commitments)
            }
            (Some(_), Some(_)) => {
                anyhow::bail!("specify either <program_path> or --pkv, not both")
            }
            (None, None) => {
                anyhow::bail!("specify <program_path> (Noir artifact JSON) or --pkv <path>")
            }
        };

        // Build the logical `CommitmentInfo` form (one entry per real
        // commitment, with `challenge_indices` flattening the per-dummy
        // K-base wires) for fingerprinting *before* `build_dump` consumes
        // the gnark-flavored dump vector. `setup_from_ceremony` operates on
        // `CommitmentInfo`, so the fingerprint must too — see the
        // `provekit_groth16::fingerprint` module docs.
        let commitment_info = build_commitment_info(&commitments);
        let fingerprint = provekit_groth16::fingerprint::fingerprint(&r1cs, &commitment_info)
            .context("computing R1CS fingerprint")?;

        let dump = build_dump(&r1cs, commitments)?;

        let out_path = self
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("circuit.r1cs.json"));

        let f =
            File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?;
        let writer = BufWriter::new(f);
        serde_json::to_writer(writer, &dump).context("serializing JSON")?;

        // Sidecar: `<out>.fingerprint`. The trusted-setup operator carries
        // this through their pipeline; `prepare --groth16-fingerprint-in`
        // reads it back and `setup_from_ceremony` verifies the ceremony
        // output binds to this exact R1CS.
        let fp_path = out_path.with_extension(match out_path.extension() {
            Some(ext) => format!("{}.fingerprint", ext.to_string_lossy()),
            None => String::from("fingerprint"),
        });
        let fp_hex = provekit_groth16::fingerprint::to_hex(&fingerprint);
        {
            let mut fp_file = File::create(&fp_path)
                .with_context(|| format!("creating {}", fp_path.display()))?;
            writeln!(fp_file, "{}", fp_hex)
                .with_context(|| format!("writing {}", fp_path.display()))?;
        }

        info!(
            num_constraints   = dump.num_constraints,
            num_witnesses     = dump.num_witnesses,
            num_public_inputs = dump.num_public_inputs,
            num_commitments   = dump.commitments.len(),
            path              = %out_path.display(),
            fingerprint_path  = %fp_path.display(),
            fingerprint       = %fp_hex,
            "exported R1CS to JSON with fingerprint sidecar"
        );

        Ok(())
    }
}

/// Collapse the N-dummy gnark commitment dump into one logical
/// [`CommitmentInfo`] per real BSB22 commitment, matching the form
/// `setup_from_ceremony` sees at import time. Entries [1..N] of the dump
/// share `public_and_commitment_committed` / `nb_public_committed` with
/// entry [0] and carry one extra K-base slot apiece via their
/// `commitment_wire`, so we fold those wires into the single entry's
/// `challenge_indices`.
fn build_commitment_info(dump: &[CommitmentDump]) -> Vec<CommitmentInfo> {
    if dump.is_empty() {
        return Vec::new();
    }
    let head = &dump[0];
    vec![CommitmentInfo {
        private_committed:               head.private_committed.clone(),
        public_and_commitment_committed: head.public_and_commitment_committed.clone(),
        challenge_indices:               dump.iter().map(|d| d.commitment_wire).collect(),
        nb_public_committed:             head.nb_public_committed,
    }]
}

fn build_dump(r1cs: &R1CS, commitments: Vec<CommitmentDump>) -> Result<R1CSDump> {
    let n = r1cs.num_constraints();
    let mut constraints = Vec::with_capacity(n);

    for j in 0..n {
        constraints.push(ConstraintRow {
            a: row_terms(r1cs, j, MatrixSel::A)?,
            b: row_terms(r1cs, j, MatrixSel::B)?,
            c: row_terms(r1cs, j, MatrixSel::C)?,
        });
    }

    Ok(R1CSDump {
        num_public_inputs: r1cs.num_public_inputs,
        num_witnesses: r1cs.num_witnesses(),
        num_constraints: n,
        constraints,
        commitments,
    })
}

#[derive(Copy, Clone)]
enum MatrixSel {
    A,
    B,
    C,
}

fn row_terms(r1cs: &R1CS, j: usize, sel: MatrixSel) -> Result<Vec<Term>> {
    let matrix = match sel {
        MatrixSel::A => &r1cs.a,
        MatrixSel::B => &r1cs.b,
        MatrixSel::C => &r1cs.c,
    };

    matrix
        .iter_row(j)
        .map(|(col, interned)| {
            let fe = r1cs
                .interner
                .get(interned)
                .ok_or_else(|| anyhow::anyhow!("R1CS interner missing value at row {j}"))?;
            Ok(Term(col, fe_to_hex(&fe)))
        })
        .collect()
}

/// Big-endian hex representation of a BN254 scalar, `0x`-prefixed and
/// zero-padded to 32 bytes (64 hex chars). The Go importer parses canonical
/// big-endian bytes via `fr.Element.SetBytes`; matching format here avoids
/// any endian fiddling on the other side.
fn fe_to_hex(fe: &FieldElement) -> String {
    use std::fmt::Write;
    // BigInt<4>::to_bytes_le is fixed-width (32 bytes); reverse for BE.
    let mut bytes = fe.into_bigint().to_bytes_le();
    bytes.reverse();
    debug_assert_eq!(bytes.len(), 32);
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
