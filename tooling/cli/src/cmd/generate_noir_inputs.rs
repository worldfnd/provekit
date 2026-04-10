use {
    crate::Command,
    anyhow::{ensure, Context, Result},
    argh::FromArgs,
    ark_ff::{PrimeField, Zero},
    ark_serialize::CanonicalDeserialize,
    provekit_common::{
        file::read, FieldElement, NoirProof, TranscriptSponge, Verifier, WhirR1CSScheme,
    },
    provekit_verifier::Verify,
    sha3::{Digest, Sha3_512},
    std::{
        fmt::Write as FmtWrite,
        fs::{self, File},
        io::Write,
        path::PathBuf,
    },
    tracing::{info, instrument},
    whir::{
        hash::{Hash, ENGINES},
        protocols::{
            challenge_indices::challenge_indices, geometric_challenge::geometric_challenge,
            irs_commit, proof_of_work,
        },
        transcript::{Proof as WhirProof, VerifierMessage, VerifierState},
    },
};

/// Generate input files for the Noir recursive verifier circuit.
///
/// Extracts WHIR configuration constants and proof data needed by the
/// Noir recursive verifier. Outputs:
/// - Prover.toml (for verifier-noir)
/// - noir_verifier_data.json (raw extracted config)
/// - synchronized src/types.nr constants
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-noir-inputs")]
pub struct Args {
    /// path to the verifier data file (.pkp)
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file (.np or .json)
    #[argh(positional)]
    proof_path: PathBuf,

    /// output path for the Noir Prover.toml
    #[argh(
        option,
        long = "output",
        default = "String::from(\"./provekit/verifier-noir/Prover.toml\")"
    )]
    output_path: String,

    /// output path for supplementary JSON data
    #[argh(
        option,
        long = "json",
        default = "String::from(\"./provekit/verifier-noir/noir_verifier_data.json\")"
    )]
    json_path: String,

    /// path to verifier-noir types.nr to auto-sync constants
    #[argh(
        option,
        long = "types",
        default = "String::from(\"./provekit/verifier-noir/src/types.nr\")"
    )]
    types_path: String,
}

/// SHA3-512(CBOR(WhirR1CSScheme)) -- matches whir::transcript::DomainSeparator::protocol().
fn compute_protocol_id(scheme: &WhirR1CSScheme) -> [u8; 64] {
    let mut hash = Sha3_512::default();
    ciborium::into_writer(scheme, &mut hash).expect("CBOR serialization of scheme failed");
    hash.finalize().into()
}

fn field_str(f: &FieldElement) -> String {
    format!("{f}")
}

/// Parse a 32-byte LE field element from a byte slice at the given offset.
fn parse_field(narg: &[u8], offset: usize) -> FieldElement {
    let bytes: [u8; 32] = narg[offset..offset + 32].try_into().unwrap();
    FieldElement::from_le_bytes_mod_order(&bytes)
}

/// Parse a 32-byte hash from a byte slice at the given offset.
fn parse_hash(narg: &[u8], offset: usize) -> [u8; 32] {
    narg[offset..offset + 32].try_into().unwrap()
}

/// Convert a 32-byte LE Skyscraper hash output to a quoted Field decimal string.
///
/// Skyscraper's `compress(l, r)` outputs a single BN254 field element, which
/// the WHIR `Hash` type stores as 32 LE bytes (`into_bigint().to_bytes_le()`).
/// The Noir verifier consumes these as `Field` values, so we re-decode them
/// here. This is only valid when the proof was produced with `HashConfig::Skyscraper`.
fn hash_field_str(hash: &[u8; 32]) -> String {
    let f = FieldElement::from_le_bytes_mod_order(hash);
    format!("\"{f}\"")
}

/// Parse a u64 (LE 8 bytes) from a byte slice at the given offset.
fn parse_u64_le(narg: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = narg[offset..offset + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Parse a WHIR quadratic sumcheck section from the narg_string.
/// Returns (coefficients, pow_nonces, bytes_consumed).
fn parse_whir_sumcheck(
    narg: &[u8],
    pos: usize,
    num_rounds: usize,
    pow_active: bool,
) -> (Vec<[FieldElement; 2]>, Vec<u64>, usize) {
    let mut offset = pos;
    let mut coeffs = Vec::with_capacity(num_rounds);
    let mut pow_nonces = Vec::new();

    for _ in 0..num_rounds {
        let c0 = parse_field(narg, offset);
        offset += 32;
        let c2 = parse_field(narg, offset);
        offset += 32;
        coeffs.push([c0, c2]);

        if pow_active {
            pow_nonces.push(parse_u64_le(narg, offset));
            offset += 8;
        }
    }

    (coeffs, pow_nonces, offset - pos)
}

#[derive(Clone, Debug)]
struct MerkleOpening {
    leaves:    Vec<Vec<FieldElement>>,
    siblings:  Vec<Vec<[u8; 32]>>,
    indices:   Vec<u32>,
    height:    usize,
    leaf_size: usize,
}

#[derive(Clone, Debug)]
struct MerkleExtraction {
    inner_round:     Vec<MerkleOpening>,
    inner_final:     MerkleOpening,
    blinding_round:  Vec<MerkleOpening>,
    blinding_final:  MerkleOpening,
}

fn decode_field_vec_hint(hints: &mut &[u8]) -> Result<Vec<FieldElement>> {
    let before = *hints;
    let mut cursor = before;
    let values = Vec::<FieldElement>::deserialize_compressed(&mut cursor)
        .context("failed to decode prover_hint_ark<Vec<FieldElement>>")?;
    let consumed = before.len().saturating_sub(cursor.len());
    ensure!(consumed > 0, "zero-byte prover_hint_ark decode");
    *hints = cursor;
    Ok(values)
}

fn decode_hash_hint(hints: &mut &[u8]) -> Result<Hash> {
    ensure!(
        hints.len() >= 32,
        "not enough hint bytes while decoding Merkle sibling hash"
    );
    let (head, tail) = hints.split_at(32);
    *hints = tail;
    Ok(Hash(head.try_into().expect("split_at guarantees 32-byte slice")))
}

fn field_row_to_bytes(row: &[FieldElement]) -> Vec<u8> {
    let mut out = Vec::with_capacity(row.len() * 32);
    for value in row {
        let limbs = value.into_bigint();
        #[cfg(not(target_endian = "little"))]
        compile_error!("This crate requires little-endian targets.");
        let bytes = limbs.as_ref();
        for limb in bytes {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
    out
}

fn hash_rows(leaf_hash_id: whir::engines::EngineId, rows: &[Vec<FieldElement>]) -> Result<Vec<Hash>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let row_size = rows[0].len();
    ensure!(row_size > 0, "cannot hash empty-width matrix rows");
    ensure!(
        rows.iter().all(|r| r.len() == row_size),
        "inconsistent row width while hashing Merkle leaves"
    );
    let message_size = row_size * 32;
    let mut input = Vec::with_capacity(rows.len() * message_size);
    for row in rows {
        input.extend_from_slice(&field_row_to_bytes(row));
    }
    let engine = ENGINES
        .retrieve(leaf_hash_id)
        .context("missing WHIR leaf hash engine")?;
    let mut out = vec![Hash::default(); rows.len()];
    engine.hash_many(message_size, &input, &mut out);
    Ok(out)
}

fn hash_pair(layer_hash_id: whir::engines::EngineId, left: Hash, right: Hash) -> Result<Hash> {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&left.0);
    input[32..].copy_from_slice(&right.0);
    let engine = ENGINES
        .retrieve(layer_hash_id)
        .context("missing WHIR Merkle layer hash engine")?;
    let mut out = [Hash::default(); 1];
    engine.hash_many(64, &input, &mut out);
    Ok(out[0])
}

fn decode_opening(
    hints: &mut &[u8],
    committer: &irs_commit::Config<whir::algebra::embedding::Identity<FieldElement>>,
    indices: &[usize],
    expected_root: [u8; 32],
) -> Result<MerkleOpening> {
    let matrix = decode_field_vec_hint(hints)?;
    let row_size = committer.matrix_commit.num_cols;
    ensure!(
        matrix.len() == indices.len() * row_size,
        "opened matrix hint length mismatch: got {}, expected {}",
        matrix.len(),
        indices.len() * row_size
    );

    let rows = matrix
        .chunks_exact(row_size)
        .map(|row| row.to_vec())
        .collect::<Vec<_>>();
    let leaf_hashes = hash_rows(committer.matrix_commit.leaf_hash_id, &rows)?;
    let mut paths = vec![Vec::<[u8; 32]>::new(); indices.len()];

    #[derive(Clone)]
    struct State {
        idx:         usize,
        hash:        Hash,
        descendants: Vec<usize>,
    }

    let mut states = indices
        .iter()
        .copied()
        .enumerate()
        .map(|(q, idx)| State {
            idx,
            hash: leaf_hashes[q],
            descendants: vec![q],
        })
        .collect::<Vec<_>>();

    // Merge duplicate query indices and enforce equal opened rows.
    states.sort_unstable_by_key(|s| s.idx);
    let mut deduped = Vec::<State>::new();
    for s in states {
        if let Some(last) = deduped.last_mut() {
            if last.idx == s.idx {
                ensure!(
                    last.hash == s.hash,
                    "duplicate query index {} has inconsistent opened row values",
                    s.idx
                );
                last.descendants.extend(s.descendants);
                continue;
            }
        }
        deduped.push(s);
    }
    let mut states = deduped;

    for layer in committer.matrix_commit.merkle_tree.layers.iter().rev() {
        let mut next = Vec::<State>::with_capacity(states.len());
        let mut i = 0usize;
        while i < states.len() {
            if i + 1 < states.len() && states[i + 1].idx == (states[i].idx ^ 1) {
                let left = states[i].clone();
                let right = states[i + 1].clone();
                for &q in &left.descendants {
                    paths[q].push(right.hash.0);
                }
                for &q in &right.descendants {
                    paths[q].push(left.hash.0);
                }
                let parent = hash_pair(layer.hash_id, left.hash, right.hash)?;
                let mut descendants = left.descendants;
                descendants.extend(right.descendants);
                next.push(State {
                    idx: left.idx >> 1,
                    hash: parent,
                    descendants,
                });
                i += 2;
            } else {
                let single = states[i].clone();
                let sibling = decode_hash_hint(hints)?;
                for &q in &single.descendants {
                    paths[q].push(sibling.0);
                }
                let parent = if (single.idx & 1) == 0 {
                    hash_pair(layer.hash_id, single.hash, sibling)?
                } else {
                    hash_pair(layer.hash_id, sibling, single.hash)?
                };
                next.push(State {
                    idx: single.idx >> 1,
                    hash: parent,
                    descendants: single.descendants,
                });
                i += 1;
            }
        }
        states = next;
    }

    ensure!(
        states.len() == 1 && states[0].idx == 0,
        "invalid Merkle reconstruction state after consuming hints"
    );
    ensure!(
        states[0].hash.0 == expected_root,
        "Merkle reconstruction root mismatch after consuming hints"
    );

    Ok(MerkleOpening {
        leaves: rows,
        siblings: paths,
        indices: indices.iter().map(|&i| i as u32).collect(),
        height: committer.matrix_commit.merkle_tree.layers.len(),
        leaf_size: row_size,
    })
}

#[allow(clippy::too_many_arguments)]
fn extract_merkle_openings(
    verifier: &Verifier,
    proof: &NoirProof,
    wfw: &WhirR1CSScheme,
    num_linear_forms: usize,
    num_w_folded_evals: usize,
    num_gammas: usize,
    num_witness_variables: usize,
    initial_root_hash: [u8; 32],
    round_root_hashes: &[[u8; 32]],
    blinding_root_hash: [u8; 32],
    blinding_round_root_hashes: &[[u8; 32]],
) -> Result<MerkleExtraction> {
    let blinded = &wfw.whir_witness.blinded_commitment;
    let blinding = &wfw.whir_witness.blinding_commitment;

    ensure!(
        wfw.num_challenges == 0,
        "generate-noir-inputs currently supports only num_challenges=0"
    );

    let instance = proof.public_inputs.hash_bytes();
    let ds = wfw.create_domain_separator().instance(&instance);
    let whir_proof = WhirProof {
        narg_string: proof.whir_r1cs_proof.narg_string.clone(),
        hints: proof.whir_r1cs_proof.hints.clone(),
        #[cfg(debug_assertions)]
        pattern: proof.whir_r1cs_proof.pattern.clone(),
    };
    let mut arthur = VerifierState::new(
        &ds,
        &whir_proof,
        TranscriptSponge::from_config(verifier.hash_config),
    );

    // Phase 1 commitments
    let _initial_commitment = wfw
        .whir_witness
        .receive_commitments(&mut arthur, 1)
        .map_err(|_| anyhow::anyhow!("failed to receive initial commitments for transcript replay"))?;

    // Spartan sumcheck transcript flow
    let _: Vec<FieldElement> = arthur.verifier_message_vec(wfw.m_0);
    let _: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read sum_g during transcript replay"))?;
    let _: FieldElement = arthur.verifier_message();
    for _ in 0..wfw.m_0 {
        for _ in 0..4 {
            let _: FieldElement = arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("failed to read Spartan coeff during transcript replay"))?;
        }
        let _: FieldElement = arthur.verifier_message();
    }
    let _: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read blinding_eval during transcript replay"))?;

    // Public-input and eval claims
    let _: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read public_inputs_hash during transcript replay"))?;
    let _: FieldElement = arthur.verifier_message();
    let _: FieldElement = arthur.prover_message().map_err(|_| anyhow::anyhow!("failed eval az"))?;
    let _: FieldElement = arthur.prover_message().map_err(|_| anyhow::anyhow!("failed eval bz"))?;
    let _: FieldElement = arthur.prover_message().map_err(|_| anyhow::anyhow!("failed eval cz"))?;
    if !proof.public_inputs.0.is_empty() {
        let _: FieldElement = arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("failed public_eval during transcript replay"))?;
    }

    // zkWHIR prelude
    let _: FieldElement = arthur.verifier_message(); // blinding challenge
    for _ in 0..num_w_folded_evals {
        let _: FieldElement = arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("failed w_folded eval during transcript replay"))?;
    }
    let _: FieldElement = arthur.verifier_message(); // masking challenge
    let zkwhir_initial_indices = challenge_indices(
        &mut arthur,
        blinded.initial_committer.matrix_commit.num_rows(),
        blinded.initial_committer.in_domain_samples,
        blinded.initial_committer.deduplicate_in_domain,
    );
    let _: FieldElement = arthur.verifier_message(); // tau1
    let _: FieldElement = arthur.verifier_message(); // tau2
    for _ in 0..num_gammas {
        let _: FieldElement = arthur
            .prover_message()
            .map_err(|_| anyhow::anyhow!("failed gamma m_eval during transcript replay"))?;
        for _ in 0..num_witness_variables {
            let _: FieldElement = arthur
                .prover_message()
                .map_err(|_| anyhow::anyhow!("failed gamma g_hat_eval during transcript replay"))?;
        }
    }
    let _: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed combined_claims during transcript replay"))?;
    let _: FieldElement = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed batched_h_claims during transcript replay"))?;

    // Inner WHIR transcript flow
    if blinded.initial_committer.out_domain_samples + num_linear_forms > 1 {
        let _: Vec<FieldElement> = geometric_challenge(&mut arthur, 2);
    }
    let mut dummy_sum = FieldElement::zero();
    blinded
        .initial_sumcheck
        .verify(&mut arthur, &mut dummy_sum)
        .map_err(|_| anyhow::anyhow!("failed initial inner WHIR sumcheck replay"))?;

    let mut inner_round_indices = Vec::<Vec<usize>>::with_capacity(blinded.round_configs.len());
    let mut current_inner_committer = &blinded.initial_committer;
    for round in &blinded.round_configs {
        let _ = round
            .irs_committer
            .receive_commitment(&mut arthur)
            .map_err(|_| anyhow::anyhow!("failed round commitment replay"))?;
        round
            .pow
            .verify(&mut arthur)
            .map_err(|_| anyhow::anyhow!("failed round pow replay"))?;
        let indices = challenge_indices(
            &mut arthur,
            current_inner_committer.matrix_commit.num_rows(),
            current_inner_committer.in_domain_samples,
            current_inner_committer.deduplicate_in_domain,
        );
        if round.irs_committer.out_domain_samples + indices.len() > 1 {
            let _: Vec<FieldElement> = geometric_challenge(&mut arthur, 2);
        }
        round
            .sumcheck
            .verify(&mut arthur, &mut dummy_sum)
            .map_err(|_| anyhow::anyhow!("failed round sumcheck replay"))?;
        inner_round_indices.push(indices);
        current_inner_committer = &round.irs_committer;
    }

    let _: Vec<FieldElement> = arthur
        .prover_messages_vec(blinded.final_sumcheck.initial_size)
        .map_err(|_| anyhow::anyhow!("failed final vector replay"))?;
    blinded
        .final_pow
        .verify(&mut arthur)
        .map_err(|_| anyhow::anyhow!("failed final pow replay"))?;
    let inner_final_indices = challenge_indices(
        &mut arthur,
        current_inner_committer.matrix_commit.num_rows(),
        current_inner_committer.in_domain_samples,
        current_inner_committer.deduplicate_in_domain,
    );
    blinded
        .final_sumcheck
        .verify(&mut arthur, &mut dummy_sum)
        .map_err(|_| anyhow::anyhow!("failed inner final sumcheck replay"))?;

    // Blinding WHIR transcript flow
    if blinding.initial_committer.num_vectors > 1 {
        let _: Vec<FieldElement> =
            geometric_challenge(&mut arthur, blinding.initial_committer.num_vectors);
    }
    if blinding.initial_committer.out_domain_samples + num_linear_forms > 1 {
        let _: Vec<FieldElement> = geometric_challenge(&mut arthur, 2);
    }
    let mut blinding_dummy_sum = FieldElement::zero();
    blinding
        .initial_sumcheck
        .verify(&mut arthur, &mut blinding_dummy_sum)
        .map_err(|_| anyhow::anyhow!("failed blinding initial sumcheck replay"))?;

    let mut blinding_round_indices = Vec::<Vec<usize>>::with_capacity(blinding.round_configs.len());
    let mut current_blinding_committer = &blinding.initial_committer;
    for round in &blinding.round_configs {
        let _ = round
            .irs_committer
            .receive_commitment(&mut arthur)
            .map_err(|_| anyhow::anyhow!("failed blinding round commitment replay"))?;
        round
            .pow
            .verify(&mut arthur)
            .map_err(|_| anyhow::anyhow!("failed blinding round pow replay"))?;
        let indices = challenge_indices(
            &mut arthur,
            current_blinding_committer.matrix_commit.num_rows(),
            current_blinding_committer.in_domain_samples,
            current_blinding_committer.deduplicate_in_domain,
        );
        if round.irs_committer.out_domain_samples + indices.len() > 1 {
            let _: Vec<FieldElement> = geometric_challenge(&mut arthur, 2);
        }
        round
            .sumcheck
            .verify(&mut arthur, &mut blinding_dummy_sum)
            .map_err(|_| anyhow::anyhow!("failed blinding round sumcheck replay"))?;
        blinding_round_indices.push(indices);
        current_blinding_committer = &round.irs_committer;
    }

    let _: Vec<FieldElement> = arthur
        .prover_messages_vec(blinding.final_sumcheck.initial_size)
        .map_err(|_| anyhow::anyhow!("failed blinding final vector replay"))?;
    blinding
        .final_pow
        .verify(&mut arthur)
        .map_err(|_| anyhow::anyhow!("failed blinding final pow replay"))?;
    let blinding_final_indices = challenge_indices(
        &mut arthur,
        current_blinding_committer.matrix_commit.num_rows(),
        current_blinding_committer.in_domain_samples,
        current_blinding_committer.deduplicate_in_domain,
    );
    blinding
        .final_sumcheck
        .verify(&mut arthur, &mut blinding_dummy_sum)
        .map_err(|_| anyhow::anyhow!("failed blinding final sumcheck replay"))?;

    // Decode hints in the exact opening order.
    let mut hints = proof.whir_r1cs_proof.hints.as_slice();

    // 1) zkWHIR initial opening (consumed for order; not directly emitted)
    let _ = decode_opening(
        &mut hints,
        &blinded.initial_committer,
        &zkwhir_initial_indices,
        initial_root_hash,
    )?;

    // 2) Inner per-round openings (open previous commitment each round)
    let mut inner_round_openings = Vec::with_capacity(inner_round_indices.len());
    for (r, indices) in inner_round_indices.iter().enumerate() {
        let committer = if r == 0 {
            &blinded.initial_committer
        } else {
            &blinded.round_configs[r - 1].irs_committer
        };
        let root = if r == 0 {
            initial_root_hash
        } else {
            round_root_hashes[r - 1]
        };
        inner_round_openings.push(decode_opening(&mut hints, committer, indices, root)?);
    }

    // 3) Inner final opening
    let inner_final_committer = if blinded.round_configs.is_empty() {
        &blinded.initial_committer
    } else {
        &blinded.round_configs[blinded.round_configs.len() - 1].irs_committer
    };
    let inner_final_root = if round_root_hashes.is_empty() {
        initial_root_hash
    } else {
        round_root_hashes[round_root_hashes.len() - 1]
    };
    let inner_final_opening = decode_opening(
        &mut hints,
        inner_final_committer,
        &inner_final_indices,
        inner_final_root,
    )?;

    // 4) Blinding per-round openings
    let mut blinding_round_openings = Vec::with_capacity(blinding_round_indices.len());
    for (r, indices) in blinding_round_indices.iter().enumerate() {
        let committer = if r == 0 {
            &blinding.initial_committer
        } else {
            &blinding.round_configs[r - 1].irs_committer
        };
        let root = if r == 0 {
            blinding_root_hash
        } else {
            blinding_round_root_hashes[r - 1]
        };
        blinding_round_openings.push(decode_opening(&mut hints, committer, indices, root)?);
    }

    // 5) Blinding final opening
    let blinding_final_committer = if blinding.round_configs.is_empty() {
        &blinding.initial_committer
    } else {
        &blinding.round_configs[blinding.round_configs.len() - 1].irs_committer
    };
    let blinding_final_root = if blinding_round_root_hashes.is_empty() {
        blinding_root_hash
    } else {
        blinding_round_root_hashes[blinding_round_root_hashes.len() - 1]
    };
    let blinding_final_opening = decode_opening(
        &mut hints,
        blinding_final_committer,
        &blinding_final_indices,
        blinding_final_root,
    )?;

    ensure!(
        hints.is_empty(),
        "unconsumed hint bytes remain after Merkle extraction: {}",
        hints.len()
    );

    Ok(MerkleExtraction {
        inner_round: inner_round_openings,
        inner_final: inner_final_opening,
        blinding_round: blinding_round_openings,
        blinding_final: blinding_final_opening,
    })
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier =
            read(&self.verifier_path).context("while reading Verifier data")?;
        let proof: NoirProof = read(&self.proof_path).context("while reading proof")?;

        let wfw = verifier
            .whir_for_witness
            .as_ref()
            .context("verifier is missing whir_for_witness config")?;

        info!(
            m_0 = wfw.m_0,
            m = wfw.m,
            num_challenges = wfw.num_challenges,
            "Generating Noir verifier inputs"
        );

        // Verify the proof passes (sanity check)
        info!("Running Rust verifier as sanity check...");
        let mut verifier_clone = verifier.clone();
        verifier_clone
            .verify(&proof)
            .context("Proof verification failed")?;
        info!("Proof verified successfully");

        let protocol_id = compute_protocol_id(wfw);
        let instance = proof.public_inputs.hash_bytes();

        // === Extract WHIR config parameters ===
        let blinded = &wfw.whir_witness.blinded_commitment;
        let blinding = &wfw.whir_witness.blinding_commitment;

        let m = wfw.m;
        let m_0 = wfw.m_0;
        let initial_ff = blinded.initial_sumcheck.num_rounds;
        let num_whir_rounds = blinded.round_configs.len();
        let final_sumcheck_rounds = blinded.final_sumcheck.num_rounds;
        let final_poly_size = blinded.final_sumcheck.initial_size;
        let ood_samples = blinded.initial_committer.out_domain_samples;
        let num_vectors = blinded.initial_committer.num_vectors;
        let max_queries = blinded.initial_committer.in_domain_samples;
        let tree_height = blinded
            .initial_committer
            .matrix_commit
            .merkle_tree
            .layers
            .len();
        let pow_bits = f64::from(proof_of_work::difficulty(blinded.final_pow.threshold));

        let blinding_ood = blinding.initial_committer.out_domain_samples;
        let blinding_num_vectors = blinding.initial_committer.num_vectors;
        let blinding_whir_rounds = blinding.round_configs.len();
        let blinding_tree_height = blinding
            .initial_committer
            .matrix_commit
            .merkle_tree
            .layers
            .len();
        let blinding_queries = blinding.initial_committer.in_domain_samples;

        let interleaving_depth = blinded.initial_committer.interleaving_depth;
        let blinding_interleaving_depth = blinding.initial_committer.interleaving_depth;
        let num_witness_variables = m;
        let _num_blinding_variables = blinding.initial_sumcheck.num_rounds
            + blinding.round_configs.len() * blinding.initial_sumcheck.num_rounds
            + blinding.final_sumcheck.num_rounds;

        let has_public_inputs = !proof.public_inputs.0.is_empty();
        let num_linear_forms =
            if has_public_inputs { 4 + 1 } else { 3 + 1 }; // evals(3) + blinding(1) + optional public(1)
        let num_gammas = max_queries * interleaving_depth;
        let num_w_folded_evals = num_linear_forms * 1 * (num_witness_variables + 1);

        let initial_sc_pow_active =
            blinded.initial_sumcheck.round_pow.threshold != u64::MAX;
        let final_sc_pow_active =
            blinded.final_sumcheck.round_pow.threshold != u64::MAX;
        let final_pow_active = blinded.final_pow.threshold != u64::MAX;

        let blinding_initial_sc_pow_active =
            blinding.initial_sumcheck.round_pow.threshold != u64::MAX;
        let blinding_final_sc_pow_active =
            blinding.final_sumcheck.round_pow.threshold != u64::MAX;
        let blinding_final_pow_active = blinding.final_pow.threshold != u64::MAX;

        let blinding_ff = blinding.initial_sumcheck.num_rounds;
        let blinding_final_sc_rounds = blinding.final_sumcheck.num_rounds;
        let blinding_final_poly_size = blinding.final_sumcheck.initial_size;

        // Per-round config extraction (inner WHIR)
        let round_sc_rounds: Vec<usize> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.num_rounds)
            .collect();
        let round_ood_samples: Vec<usize> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.out_domain_samples)
            .collect();
        let _round_num_queries: Vec<usize> = (0..num_whir_rounds)
            .map(|r| {
                if r == 0 {
                    blinded.initial_committer.in_domain_samples
                } else {
                    blinded.round_configs[r - 1].irs_committer.in_domain_samples
                }
            })
            .collect();
        let round_pow_active: Vec<bool> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.pow.threshold != u64::MAX)
            .collect();
        let round_sc_pow_active: Vec<bool> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.round_pow.threshold != u64::MAX)
            .collect();

        // Per-round config extraction (blinding WHIR)
        let blinding_round_sc_rounds: Vec<usize> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.num_rounds)
            .collect();
        let blinding_round_ood_samples: Vec<usize> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.out_domain_samples)
            .collect();
        let _blinding_round_num_queries: Vec<usize> = (0..blinding_whir_rounds)
            .map(|r| {
                if r == 0 {
                    blinding.initial_committer.in_domain_samples
                } else {
                    blinding.round_configs[r - 1].irs_committer.in_domain_samples
                }
            })
            .collect();
        let blinding_round_pow_active: Vec<bool> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.pow.threshold != u64::MAX)
            .collect();
        let blinding_round_sc_pow_active: Vec<bool> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.round_pow.threshold != u64::MAX)
            .collect();

        let _final_num_queries = if num_whir_rounds == 0 {
            blinded.initial_committer.in_domain_samples
        } else {
            blinded.round_configs[num_whir_rounds - 1]
                .irs_committer
                .in_domain_samples
        };
        let _blinding_final_num_queries = if blinding_whir_rounds == 0 {
            blinding.initial_committer.in_domain_samples
        } else {
            blinding.round_configs[blinding_whir_rounds - 1]
                .irs_committer
                .in_domain_samples
        };
        let round_array_size = std::cmp::max(1, num_whir_rounds);
        let blinding_round_array_size = std::cmp::max(1, blinding_whir_rounds);
        let final_sc_array_size = std::cmp::max(1, final_sumcheck_rounds);
        let blinding_final_sc_array_size = std::cmp::max(1, blinding_final_sc_rounds);
        let blinding_final_poly_array_size = std::cmp::max(1, blinding_final_poly_size);

        info!(
            initial_ff,
            num_whir_rounds,
            final_sumcheck_rounds,
            final_poly_size,
            tree_height,
            ood_samples,
            num_vectors,
            max_queries,
            pow_bits,
            interleaving_depth,
            num_gammas,
            num_w_folded_evals,
            num_witness_variables,
            initial_sc_pow_active,
            final_sc_pow_active,
            final_pow_active,
            "Extracted WHIR config"
        );

        // === Output constants JSON ===
        let mut constants = serde_json::Map::new();
        constants.insert("LOG_NUM_CONSTRAINTS".into(), m_0.into());
        constants.insert("LOG_NUM_VARIABLES".into(), m.into());
        constants.insert("NUM_WHIR_ROUNDS".into(), num_whir_rounds.into());
        constants.insert("FOLDING_FACTOR".into(), initial_ff.into());
        constants.insert("MAX_QUERIES_PER_ROUND".into(), max_queries.into());
        constants.insert("TREE_HEIGHT".into(), tree_height.into());
        constants.insert("OOD_SAMPLES".into(), ood_samples.into());
        constants.insert("FINAL_POLY_SIZE".into(), final_poly_size.into());
        constants.insert("FINAL_SUMCHECK_ROUNDS".into(), final_sumcheck_rounds.into());
        constants.insert("FOLD_SIZE".into(), (1usize << initial_ff).into());
        constants.insert("POW_BITS".into(), (pow_bits as u32).into());
        constants.insert("MAX_PUBLIC_INPUTS".into(), proof.public_inputs.0.len().into());
        constants.insert("W1_SIZE".into(), wfw.w1_size.into());
        constants.insert("NUM_CHALLENGES".into(), wfw.num_challenges.into());
        constants.insert("BATCH_SIZE".into(), num_vectors.into());
        constants.insert("NUM_VECTORS".into(), num_vectors.into());
        constants.insert("INTERLEAVING_DEPTH".into(), interleaving_depth.into());
        constants.insert("NUM_WITNESS_VARIABLES".into(), num_witness_variables.into());
        constants.insert("NUM_LINEAR_FORMS".into(), num_linear_forms.into());
        constants.insert("NUM_W_FOLDED_EVALS".into(), num_w_folded_evals.into());
        constants.insert("NUM_GAMMAS".into(), num_gammas.into());
        constants.insert("BLINDING_OOD_SAMPLES".into(), blinding_ood.into());
        constants.insert("BLINDING_WHIR_ROUNDS".into(), blinding_whir_rounds.into());
        constants.insert("BLINDING_TREE_HEIGHT".into(), blinding_tree_height.into());
        constants.insert("BLINDING_MAX_QUERIES".into(), blinding_queries.into());
        constants.insert("BLINDING_NUM_VECTORS".into(), blinding_num_vectors.into());
        constants.insert("BLINDING_INTERLEAVING_DEPTH".into(), blinding_interleaving_depth.into());
        constants.insert("BLINDING_FOLDING_FACTOR".into(), blinding_ff.into());
        constants.insert("BLINDING_FINAL_SUMCHECK_ROUNDS".into(), blinding_final_sc_rounds.into());
        constants.insert("BLINDING_FINAL_POLY_SIZE".into(), blinding_final_poly_size.into());
        constants.insert("INITIAL_SUMCHECK_POW_ACTIVE".into(), initial_sc_pow_active.into());
        constants.insert("FINAL_SUMCHECK_POW_ACTIVE".into(), final_sc_pow_active.into());
        constants.insert("FINAL_POW_ACTIVE".into(), final_pow_active.into());
        constants.insert("BLINDING_INITIAL_SC_POW_ACTIVE".into(), blinding_initial_sc_pow_active.into());
        constants.insert("BLINDING_FINAL_SC_POW_ACTIVE".into(), blinding_final_sc_pow_active.into());
        constants.insert("BLINDING_FINAL_POW_ACTIVE".into(), blinding_final_pow_active.into());
        constants.insert("ROUND_SC_ROUNDS".into(), serde_json::to_value(&round_sc_rounds).unwrap());
        constants.insert("ROUND_OOD_SAMPLES".into(), serde_json::to_value(&round_ood_samples).unwrap());
        constants.insert("ROUND_POW_ACTIVE".into(), serde_json::to_value(&round_pow_active).unwrap());
        constants.insert("ROUND_SC_POW_ACTIVE".into(), serde_json::to_value(&round_sc_pow_active).unwrap());
        constants.insert("BLINDING_ROUND_SC_ROUNDS".into(), serde_json::to_value(&blinding_round_sc_rounds).unwrap());
        constants.insert("BLINDING_ROUND_OOD_SAMPLES".into(), serde_json::to_value(&blinding_round_ood_samples).unwrap());
        constants.insert("BLINDING_ROUND_POW_ACTIVE".into(), serde_json::to_value(&blinding_round_pow_active).unwrap());
        constants.insert("BLINDING_ROUND_SC_POW_ACTIVE".into(), serde_json::to_value(&blinding_round_sc_pow_active).unwrap());
        constants.insert("protocol_id_hex".into(), hex::encode(protocol_id).into());
        constants.insert("instance_hex".into(), hex::encode(instance).into());
        constants.insert("narg_string_len".into(), proof.whir_r1cs_proof.narg_string.len().into());
        constants.insert("hints_len".into(), proof.whir_r1cs_proof.hints.len().into());
        let constants = serde_json::Value::Object(constants);

        let mut json_file =
            File::create(&self.json_path).context("while creating JSON output")?;
        json_file
            .write_all(serde_json::to_string_pretty(&constants)?.as_bytes())
            .context("while writing JSON")?;
        info!(path = %self.json_path, "Wrote constants JSON");

        // === Parse narg_string to extract commitment data ===
        // The narg_string contains all prover messages in protocol order.
        // Format: Hash(32B) + OOD_answers(32B*ood*nvec) + Hash(32B) + blinding_OOD(32B*...) + ...
        let narg = &proof.whir_r1cs_proof.narg_string;
        let mut pos: usize = 0;

        // Initial f_hat root hash (1 polynomial)
        let initial_root_hash = parse_hash(narg, pos);
        pos += 32;

        // OOD answers: ood_samples * num_vectors field elements
        let mut initial_ood_answers = Vec::with_capacity(ood_samples * num_vectors);
        for _ in 0..(ood_samples * num_vectors) {
            initial_ood_answers.push(parse_field(narg, pos));
            pos += 32;
        }

        // Blinding root hash
        let blinding_root_hash = parse_hash(narg, pos);
        pos += 32;

        // Blinding OOD answers
        let mut blinding_ood_answers =
            Vec::with_capacity(blinding_ood * blinding_num_vectors);
        for _ in 0..(blinding_ood * blinding_num_vectors) {
            blinding_ood_answers.push(parse_field(narg, pos));
            pos += 32;
        }

        // sum_g
        let sum_g = parse_field(narg, pos);
        pos += 32;

        // Spartan sumcheck: m_0 rounds, 4 coefficients each
        let mut sumcheck_coeffs = Vec::with_capacity(m_0);
        for _ in 0..m_0 {
            let c: [FieldElement; 4] = [
                parse_field(narg, pos),
                parse_field(narg, pos + 32),
                parse_field(narg, pos + 64),
                parse_field(narg, pos + 96),
            ];
            sumcheck_coeffs.push(c);
            pos += 128;
        }

        // blinding_eval
        let blinding_eval = parse_field(narg, pos);
        pos += 32;

        // public_inputs_hash
        let public_inputs_hash = parse_field(narg, pos);
        pos += 32;

        // evals: Az, Bz, Cz
        let evals_az = parse_field(narg, pos);
        pos += 32;
        let evals_bz = parse_field(narg, pos);
        pos += 32;
        let evals_cz = parse_field(narg, pos);
        pos += 32;

        // public_eval (if applicable)
        let public_eval = if !proof.public_inputs.0.is_empty() {
            let pe = parse_field(narg, pos);
            pos += 32;
            pe
        } else {
            FieldElement::zero()
        };

        info!(
            narg_offset_after_spartan = pos,
            narg_total = narg.len(),
            remaining = narg.len() - pos,
            "Parsed Spartan-level data from narg_string"
        );

        // === Parse zkWHIR prover messages ===

        // w_folded_blinding_evals
        let mut w_folded_evals = Vec::with_capacity(num_w_folded_evals);
        for _ in 0..num_w_folded_evals {
            w_folded_evals.push(parse_field(narg, pos));
            pos += 32;
        }

        // Per-gamma block: for each gamma, for each polynomial (=1):
        //   m_eval (1 field) + g_hat_evals (num_witness_variables fields)
        let mut gamma_m_evals = Vec::with_capacity(num_gammas);
        let mut gamma_g_hat_evals = Vec::with_capacity(num_gammas * num_witness_variables);
        for _ in 0..num_gammas {
            gamma_m_evals.push(parse_field(narg, pos));
            pos += 32;
            for _ in 0..num_witness_variables {
                gamma_g_hat_evals.push(parse_field(narg, pos));
                pos += 32;
            }
        }

        // combined_claims and batched_h_claims (1 each for single polynomial)
        let combined_claims = parse_field(narg, pos);
        pos += 32;
        let batched_h_claims = parse_field(narg, pos);
        pos += 32;

        info!(
            narg_offset_after_zkwhir_claims = pos,
            "Parsed zkWHIR claims from narg_string"
        );

        // === Parse inner WHIR prover messages (blinded commitment) ===

        // Initial sumcheck: initial_ff rounds of (c0, c2) + optional PoW nonces
        let (initial_whir_coeffs, _initial_sc_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, initial_ff, initial_sc_pow_active);
        pos += consumed;

        // Per-round WHIR data
        // For each round: receive_commitment (root + OOD answers) + PoW + sumcheck
        // STIR challenges and Merkle proofs are verifier-side / in hints
        let mut round_root_hashes = Vec::with_capacity(num_whir_rounds);
        let mut round_ood_answers: Vec<Vec<FieldElement>> = Vec::with_capacity(num_whir_rounds);
        let mut round_pow_nonces = Vec::with_capacity(num_whir_rounds);
        let mut round_sumcheck_coeffs: Vec<Vec<[FieldElement; 2]>> =
            Vec::with_capacity(num_whir_rounds);

        for r in 0..num_whir_rounds {
            // receive_commitment: root hash
            round_root_hashes.push(parse_hash(narg, pos));
            pos += 32;

            // receive_commitment: OOD answers
            let mut ood_ans = Vec::with_capacity(round_ood_samples[r]);
            for _ in 0..round_ood_samples[r] {
                ood_ans.push(parse_field(narg, pos));
                pos += 32;
            }
            round_ood_answers.push(ood_ans);

            // Round PoW nonce
            let nonce = if round_pow_active[r] {
                let n = parse_u64_le(narg, pos);
                pos += 8;
                n
            } else {
                0u64
            };
            round_pow_nonces.push(nonce);

            // Round sumcheck coefficients
            let (coeffs, _round_sc_nonces, consumed) =
                parse_whir_sumcheck(narg, pos, round_sc_rounds[r], round_sc_pow_active[r]);
            pos += consumed;
            round_sumcheck_coeffs.push(coeffs);
        }

        info!(
            narg_offset_after_inner_whir_rounds = pos,
            inner_rounds_parsed = num_whir_rounds,
            "Parsed inner WHIR per-round data"
        );

        // Final vector
        let mut final_coefficients = Vec::with_capacity(final_poly_size);
        for _ in 0..final_poly_size {
            final_coefficients.push(parse_field(narg, pos));
            pos += 32;
        }

        // Final PoW nonce
        let final_pow_nonce = if final_pow_active {
            let n = parse_u64_le(narg, pos);
            pos += 8;
            n
        } else {
            0u64
        };

        // Final sumcheck
        let (final_whir_coeffs, _final_sc_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, final_sumcheck_rounds, final_sc_pow_active);
        pos += consumed;

        info!(
            narg_offset_after_inner_whir = pos,
            remaining = narg.len() - pos,
            "Parsed inner WHIR data from narg_string"
        );

        // === Parse blinding WHIR prover messages ===

        // Blinding initial sumcheck
        let (blinding_initial_coeffs, _blinding_initial_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, blinding_ff, blinding_initial_sc_pow_active);
        pos += consumed;

        // Blinding per-round data
        let mut blinding_round_root_hashes = Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_ood_ans: Vec<Vec<FieldElement>> =
            Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_pow_nonce_vec = Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_sumcheck_coeffs_vec: Vec<Vec<[FieldElement; 2]>> =
            Vec::with_capacity(blinding_whir_rounds);

        for r in 0..blinding_whir_rounds {
            blinding_round_root_hashes.push(parse_hash(narg, pos));
            pos += 32;

            let mut ood_ans = Vec::with_capacity(blinding_round_ood_samples[r]);
            for _ in 0..blinding_round_ood_samples[r] {
                ood_ans.push(parse_field(narg, pos));
                pos += 32;
            }
            blinding_round_ood_ans.push(ood_ans);

            let nonce = if blinding_round_pow_active[r] {
                let n = parse_u64_le(narg, pos);
                pos += 8;
                n
            } else {
                0u64
            };
            blinding_round_pow_nonce_vec.push(nonce);

            let (coeffs, _nonces, consumed) = parse_whir_sumcheck(
                narg,
                pos,
                blinding_round_sc_rounds[r],
                blinding_round_sc_pow_active[r],
            );
            pos += consumed;
            blinding_round_sumcheck_coeffs_vec.push(coeffs);
        }

        info!(
            narg_offset_after_blinding_whir_rounds = pos,
            blinding_rounds_parsed = blinding_whir_rounds,
            "Parsed blinding WHIR per-round data"
        );

        // Blinding final vector
        let mut blinding_final_coefficients = Vec::with_capacity(blinding_final_poly_size);
        for _ in 0..blinding_final_poly_size {
            blinding_final_coefficients.push(parse_field(narg, pos));
            pos += 32;
        }

        // Blinding final PoW nonce
        let blinding_final_pow_nonce = if blinding_final_pow_active {
            let n = parse_u64_le(narg, pos);
            pos += 8;
            n
        } else {
            0u64
        };

        // Blinding final sumcheck
        let (blinding_final_coeffs, _blinding_final_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, blinding_final_sc_rounds, blinding_final_sc_pow_active);
        pos += consumed;

        info!(
            narg_offset_after_blinding_whir = pos,
            narg_total = narg.len(),
            remaining_bytes = narg.len().saturating_sub(pos),
            "Parsed blinding WHIR data from narg_string"
        );

        if pos != narg.len() {
            info!(
                unparsed_bytes = narg.len() - pos,
                "Warning: {} unparsed bytes remain in narg_string",
                narg.len() - pos
            );
        }

        let merkle = extract_merkle_openings(
            &verifier,
            &proof,
            wfw,
            num_linear_forms,
            num_w_folded_evals,
            num_gammas,
            num_witness_variables,
            initial_root_hash,
            &round_root_hashes,
            blinding_root_hash,
            &blinding_round_root_hashes,
        )
        .context("while extracting Merkle openings from WHIR hints")?;

        let expected_inner_leaf_size = 1usize << initial_ff;
        let expected_blinding_leaf_size = blinding_num_vectors * (1usize << blinding_ff);
        for (r, opening) in merkle.inner_round.iter().enumerate() {
            ensure!(
                opening.leaf_size <= expected_inner_leaf_size,
                "inner round {r} leaf width {} exceeds max {}",
                opening.leaf_size,
                expected_inner_leaf_size
            );
            ensure!(
                opening.height <= tree_height,
                "inner round {r} Merkle height {} exceeds TREE_HEIGHT {}",
                opening.height,
                tree_height
            );
            ensure!(
                opening.indices.len() <= max_queries,
                "inner round {r} query count {} exceeds MAX_QUERIES_PER_ROUND {}",
                opening.indices.len(),
                max_queries
            );
        }
        ensure!(
            merkle.inner_final.leaf_size <= expected_inner_leaf_size,
            "inner final leaf width {} exceeds max {}",
            merkle.inner_final.leaf_size,
            expected_inner_leaf_size
        );
        ensure!(
            merkle.inner_final.height <= tree_height,
            "inner final Merkle height {} exceeds TREE_HEIGHT {}",
            merkle.inner_final.height,
            tree_height
        );
        ensure!(
            merkle.inner_final.indices.len() <= max_queries,
            "inner final query count {} exceeds MAX_QUERIES_PER_ROUND {}",
            merkle.inner_final.indices.len(),
            max_queries
        );
        for (r, opening) in merkle.blinding_round.iter().enumerate() {
            ensure!(
                opening.leaf_size <= expected_blinding_leaf_size,
                "blinding round {r} leaf width {} exceeds max {}",
                opening.leaf_size,
                expected_blinding_leaf_size
            );
            ensure!(
                opening.height <= blinding_tree_height,
                "blinding round {r} Merkle height {} exceeds BLINDING_TREE_HEIGHT {}",
                opening.height,
                blinding_tree_height
            );
            ensure!(
                opening.indices.len() <= blinding_queries,
                "blinding round {r} query count {} exceeds BLINDING_MAX_QUERIES {}",
                opening.indices.len(),
                blinding_queries
            );
        }
        ensure!(
            merkle.blinding_final.leaf_size <= expected_blinding_leaf_size,
            "blinding final leaf width {} exceeds max {}",
            merkle.blinding_final.leaf_size,
            expected_blinding_leaf_size
        );
        ensure!(
            merkle.blinding_final.height <= blinding_tree_height,
            "blinding final Merkle height {} exceeds BLINDING_TREE_HEIGHT {}",
            merkle.blinding_final.height,
            blinding_tree_height
        );
        ensure!(
            merkle.blinding_final.indices.len() <= blinding_queries,
            "blinding final query count {} exceeds BLINDING_MAX_QUERIES {}",
            merkle.blinding_final.indices.len(),
            blinding_queries
        );

        // === Extract R1CS matrices ===
        let r1cs = &verifier.r1cs;
        let ha = r1cs.a();
        let hb = r1cs.b();
        let hc = r1cs.c();

        let mut a_cells: Vec<(u32, u32, FieldElement)> = Vec::new();
        let mut b_cells: Vec<(u32, u32, FieldElement)> = Vec::new();
        let mut c_cells: Vec<(u32, u32, FieldElement)> = Vec::new();

        for row in 0..r1cs.a.num_rows {
            for (col, val) in ha.iter_row(row) {
                a_cells.push((row as u32, col as u32, val));
            }
        }
        for row in 0..r1cs.b.num_rows {
            for (col, val) in hb.iter_row(row) {
                b_cells.push((row as u32, col as u32, val));
            }
        }
        for row in 0..r1cs.c.num_rows {
            for (col, val) in hc.iter_row(row) {
                c_cells.push((row as u32, col as u32, val));
            }
        }

        info!(
            a_nnz = a_cells.len(),
            b_nnz = b_cells.len(),
            c_nnz = c_cells.len(),
            "Extracted R1CS matrices"
        );

        sync_types_file(
            &self.types_path,
            m_0 as u32,
            m as u32,
            num_whir_rounds as u32,
            initial_ff as u32,
            max_queries as u32,
            tree_height as u32,
            ood_samples as u32,
            ((blinded.initial_committer.codeword_length.ilog2() as usize).saturating_sub(m)) as u32,
            pow_bits.round() as u32,
            proof.public_inputs.0.len() as u32,
            std::cmp::max(a_cells.len(), std::cmp::max(b_cells.len(), c_cells.len())) as u32,
            wfw.num_challenges as u32,
            wfw.w1_size as u32,
            num_vectors as u32,
            blinding_ood as u32,
            blinding_whir_rounds as u32,
            blinding_tree_height as u32,
            blinding_num_vectors as u32,
            num_witness_variables as u32,
            blinding_queries as u32,
            num_linear_forms as u32,
            num_w_folded_evals as u32,
            final_poly_size as u32,
            blinding_final_poly_size as u32,
            final_sumcheck_rounds as u32,
            blinding_final_sc_rounds as u32,
            num_gammas as u32,
        )?;
        info!(path = %self.types_path, "Synchronized verifier-noir types.nr constants");

        // === Write Prover.toml ===
        let mut out = String::new();
        writeln!(out, "# ProveKit Noir Recursive Verifier Inputs")?;
        writeln!(out, "# Generated by `provekit generate-noir-inputs`")?;
        writeln!(out, "# Config: m_0={m_0}, m={m}, rounds={num_whir_rounds}")?;
        writeln!(out)?;

        write_byte_array(&mut out, "protocol_id", &protocol_id)?;
        write_byte_array(&mut out, "instance", &instance)?;
        writeln!(out)?;

        writeln!(out, "initial_root_hash = {}", hash_field_str(&initial_root_hash))?;
        write_field_array(&mut out, "initial_ood_answers", &initial_ood_answers)?;
        writeln!(out, "blinding_root_hash = {}", hash_field_str(&blinding_root_hash))?;
        write_field_array(&mut out, "blinding_ood_answers", &blinding_ood_answers)?;
        writeln!(out)?;

        writeln!(out, "sum_g = \"{}\"", field_str(&sum_g))?;
        writeln!(out, "blinding_eval = \"{}\"", field_str(&blinding_eval))?;
        writeln!(out)?;

        writeln!(out, "sumcheck_coeffs = [")?;
        for (i, coeffs) in sumcheck_coeffs.iter().enumerate() {
            let comma = if i < sumcheck_coeffs.len() - 1 { "," } else { "" };
            writeln!(
                out,
                "  [\"{}\", \"{}\", \"{}\", \"{}\"]{}",
                field_str(&coeffs[0]),
                field_str(&coeffs[1]),
                field_str(&coeffs[2]),
                field_str(&coeffs[3]),
                comma
            )?;
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        writeln!(out, "num_public_inputs = {}", proof.public_inputs.0.len())?;
        if proof.public_inputs.0.is_empty() {
            writeln!(out, "public_inputs = [\"0\"]")?;
        } else {
            write_field_array(&mut out, "public_inputs", &proof.public_inputs.0)?;
        }
        writeln!(out, "public_inputs_hash_from_prover = \"{}\"", field_str(&public_inputs_hash))?;
        writeln!(out, "evals_az = \"{}\"", field_str(&evals_az))?;
        writeln!(out, "evals_bz = \"{}\"", field_str(&evals_bz))?;
        writeln!(out, "evals_cz = \"{}\"", field_str(&evals_cz))?;
        writeln!(out, "public_eval = \"{}\"", field_str(&public_eval))?;
        writeln!(out)?;

        // === zkWHIR data ===
        writeln!(out, "# --- Phase 4: zkWHIR ---")?;
        write_field_array(&mut out, "w_folded_evals", &w_folded_evals)?;
        writeln!(out)?;

        writeln!(out, "num_gammas = {num_gammas}")?;
        write_field_array(&mut out, "gamma_m_evals", &gamma_m_evals)?;
        // gamma_g_hat_evals is a 2D array: [MAX_GAMMAS][NUM_WITNESS_VARIABLES]
        writeln!(out, "gamma_g_hat_evals = [")?;
        for g in 0..num_gammas {
            let start = g * num_witness_variables;
            let end = start + num_witness_variables;
            let row: Vec<String> = gamma_g_hat_evals[start..end]
                .iter()
                .map(|f| format!("\"{}\"", field_str(f)))
                .collect();
            let comma = if g < num_gammas - 1 { "," } else { "" };
            writeln!(out, "  [{}]{comma}", row.join(", "))?;
        }
        writeln!(out, "]")?;
        writeln!(out, "combined_claims = \"{}\"", field_str(&combined_claims))?;
        writeln!(out, "batched_h_claims = \"{}\"", field_str(&batched_h_claims))?;
        writeln!(out)?;

        // === Inner WHIR data ===
        writeln!(out, "# --- Phase 4a: Inner WHIR (blinded) ---")?;
        writeln!(out, "initial_whir_sumcheck_coeffs = [")?;
        for (i, c) in initial_whir_coeffs.iter().enumerate() {
            let comma = if i < initial_whir_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;

        write_field_array(&mut out, "final_coefficients", &final_coefficients)?;
        writeln!(out, "final_pow_nonce = {final_pow_nonce}")?;
        writeln!(out, "final_num_queries = {}", merkle.inner_final.indices.len())?;

        writeln!(out, "final_whir_sumcheck_coeffs = [")?;
        for i in 0..final_sc_array_size {
            if i < final_whir_coeffs.len() {
                let c = final_whir_coeffs[i];
                let comma = if i < final_sc_array_size - 1 { "," } else { "" };
                writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
            } else {
                let comma = if i < final_sc_array_size - 1 { "," } else { "" };
                writeln!(out, "  [\"0\", \"0\"]{comma}")?;
            }
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        // Per-round WHIR data
        writeln!(out, "# Per-round WHIR data ({num_whir_rounds} rounds)")?;
        writeln!(out, "round_root_hashes = [")?;
        for r in 0..round_array_size {
            let comma = if r < round_array_size - 1 { "," } else { "" };
            if r < round_root_hashes.len() {
                writeln!(out, "  {}{comma}", hash_field_str(&round_root_hashes[r]))?;
            } else {
                writeln!(out, "  \"0\"{comma}")?;
            }
        }
        writeln!(out, "]")?;

        writeln!(out, "round_ood_answers = [")?;
        for r in 0..round_array_size {
            let comma = if r < round_array_size - 1 { "," } else { "" };
            if r < round_ood_answers.len() {
                let vals: Vec<String> = round_ood_answers[r]
                    .iter()
                    .map(|f| format!("\"{}\"", field_str(f)))
                    .collect();
                writeln!(out, "  [{}]{comma}", vals.join(", "))?;
            } else {
                writeln!(out, "  [\"0\"]{comma}")?;
            }
        }
        writeln!(out, "]")?;

        writeln!(out, "round_whir_sumcheck_coeffs = [")?;
        for r in 0..round_array_size {
            write!(out, "  [")?;
            if r < round_sumcheck_coeffs.len() {
                let coeffs = &round_sumcheck_coeffs[r];
                for i in 0..initial_ff {
                    if i < coeffs.len() {
                        let c = coeffs[i];
                        let comma = if i < initial_ff - 1 { ", " } else { "" };
                        write!(out, "[\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
                    } else {
                        let comma = if i < initial_ff - 1 { ", " } else { "" };
                        write!(out, "[\"0\", \"0\"]{comma}")?;
                    }
                }
            } else {
                for i in 0..initial_ff {
                    let comma = if i < initial_ff - 1 { ", " } else { "" };
                    write!(out, "[\"0\", \"0\"]{comma}")?;
                }
            }
            let comma = if r < round_array_size - 1 { "," } else { "" };
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;

        writeln!(
            out,
            "round_pow_nonces = [{}]",
            (0..round_array_size)
                .map(|r| {
                    if r < round_pow_nonces.len() {
                        round_pow_nonces[r].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "round_num_queries = [{}]",
            (0..round_array_size)
                .map(|r| {
                    if r < merkle.inner_round.len() {
                        merkle.inner_round[r].indices.len().to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out, "round_merkle_leaves = [")?;
        for r in 0..round_array_size {
            let comma = if r < round_array_size - 1 { "," } else { "" };
            write!(out, "  [")?;
            for q in 0..max_queries {
                let q_comma = if q < max_queries - 1 { ", " } else { "" };
                if r < merkle.inner_round.len() && q < merkle.inner_round[r].leaves.len() {
                    let mut vals = merkle.inner_round[r].leaves[q]
                        .iter()
                        .map(|f| format!("\"{}\"", field_str(f)))
                        .collect::<Vec<_>>();
                    vals.extend(std::iter::repeat_n(
                        "\"0\"".to_string(),
                        expected_inner_leaf_size.saturating_sub(vals.len()),
                    ));
                    write!(out, "[{}]{q_comma}", vals.join(", "))?;
                } else {
                    write!(
                        out,
                        "[{}]{q_comma}",
                        vec!["\"0\""; 1usize << initial_ff].join(", ")
                    )?;
                }
            }
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;
        writeln!(out, "round_merkle_siblings = [")?;
        for r in 0..round_array_size {
            let comma = if r < round_array_size - 1 { "," } else { "" };
            write!(out, "  [")?;
            for q in 0..max_queries {
                let q_comma = if q < max_queries - 1 { ", " } else { "" };
                if r < merkle.inner_round.len() && q < merkle.inner_round[r].siblings.len() {
                    let sibs = (0..tree_height)
                        .map(|h| {
                            if h < merkle.inner_round[r].siblings[q].len() {
                                hash_field_str(&merkle.inner_round[r].siblings[q][h])
                            } else {
                                "\"0\"".to_string()
                            }
                        })
                        .collect::<Vec<_>>();
                    write!(out, "[{}]{q_comma}", sibs.join(", "))?;
                } else {
                    write!(
                        out,
                        "[{}]{q_comma}",
                        vec!["\"0\""; tree_height].join(", ")
                    )?;
                }
            }
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;
        writeln!(out, "round_merkle_indices = [")?;
        for r in 0..round_array_size {
            let comma = if r < round_array_size - 1 { "," } else { "" };
            let row = (0..max_queries)
                .map(|q| {
                    if r < merkle.inner_round.len() && q < merkle.inner_round[r].indices.len() {
                        merkle.inner_round[r].indices[q].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>();
            writeln!(out, "  [{}]{comma}", row.join(", "))?;
        }
        writeln!(out, "]")?;
        writeln!(
            out,
            "round_merkle_leaf_sizes = [{}]",
            (0..round_array_size)
                .map(|r| {
                    if r < merkle.inner_round.len() {
                        merkle.inner_round[r].leaf_size.to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "round_merkle_tree_heights = [{}]",
            (0..round_array_size)
                .map(|r| {
                    if r < merkle.inner_round.len() {
                        merkle.inner_round[r].height.to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out)?;

        // Final Merkle proofs
        writeln!(out, "# Final Merkle proofs")?;
        writeln!(
            out,
            "final_merkle_leaves = [{}]",
            (0..max_queries)
                .map(|q| {
                    if q < merkle.inner_final.leaves.len() {
                        let mut vals = merkle.inner_final.leaves[q]
                            .iter()
                            .map(|f| format!("\"{}\"", field_str(f)))
                            .collect::<Vec<_>>();
                        vals.extend(std::iter::repeat_n(
                            "\"0\"".to_string(),
                            expected_inner_leaf_size.saturating_sub(vals.len()),
                        ));
                        format!("[{}]", vals.join(", "))
                    } else {
                        format!("[{}]", vec!["\"0\""; 1usize << initial_ff].join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "final_merkle_siblings = [{}]",
            (0..max_queries)
                .map(|q| {
                    let sibs = (0..tree_height)
                        .map(|h| {
                            if q < merkle.inner_final.siblings.len()
                                && h < merkle.inner_final.siblings[q].len()
                            {
                                hash_field_str(&merkle.inner_final.siblings[q][h])
                            } else {
                                "\"0\"".to_string()
                            }
                        })
                        .collect::<Vec<_>>();
                    format!("[{}]", sibs.join(", "))
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "final_merkle_indices = [{}]",
            (0..max_queries)
                .map(|q| {
                    if q < merkle.inner_final.indices.len() {
                        merkle.inner_final.indices[q].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out, "final_merkle_leaf_size = {}", merkle.inner_final.leaf_size)?;
        writeln!(
            out,
            "final_merkle_tree_height = {}",
            merkle.inner_final.height
        )?;
        writeln!(out)?;

        // === Blinding WHIR data ===
        writeln!(out, "# --- Phase 4b: Blinding WHIR ---")?;
        writeln!(out, "blinding_whir_initial_coeffs = [")?;
        for (i, c) in blinding_initial_coeffs.iter().enumerate() {
            let comma = if i < blinding_initial_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;

        if blinding_final_coefficients.is_empty() {
            writeln!(out, "blinding_final_coefficients = [\"0\"]")?;
        } else if blinding_final_coefficients.len() < blinding_final_poly_array_size {
            let mut vals: Vec<String> = blinding_final_coefficients
                .iter()
                .map(|f| format!("\"{}\"", field_str(f)))
                .collect();
            vals.extend(std::iter::repeat_n("\"0\"".to_string(), blinding_final_poly_array_size - blinding_final_coefficients.len()));
            writeln!(out, "blinding_final_coefficients = [{}]", vals.join(", "))?;
        } else {
            write_field_array(&mut out, "blinding_final_coefficients", &blinding_final_coefficients)?;
        }
        writeln!(out, "blinding_final_pow_nonce = {blinding_final_pow_nonce}")?;
        writeln!(
            out,
            "blinding_final_num_queries = {}",
            merkle.blinding_final.indices.len()
        )?;

        writeln!(out, "blinding_final_sumcheck_coeffs = [")?;
        for i in 0..blinding_final_sc_array_size {
            if i < blinding_final_coeffs.len() {
                let c = blinding_final_coeffs[i];
                let comma = if i < blinding_final_sc_array_size - 1 { "," } else { "" };
                writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
            } else {
                let comma = if i < blinding_final_sc_array_size - 1 { "," } else { "" };
                writeln!(out, "  [\"0\", \"0\"]{comma}")?;
            }
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        // Blinding per-round data
        writeln!(out, "# Blinding per-round data ({blinding_whir_rounds} rounds)")?;
        writeln!(out, "blinding_round_root_hashes = [")?;
        for r in 0..blinding_round_array_size {
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            if r < blinding_round_root_hashes.len() {
                writeln!(out, "  {}{comma}", hash_field_str(&blinding_round_root_hashes[r]))?;
            } else {
                writeln!(out, "  \"0\"{comma}")?;
            }
        }
        writeln!(out, "]")?;

        writeln!(out, "blinding_round_ood_answers = [")?;
        for r in 0..blinding_round_array_size {
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            if r < blinding_round_ood_ans.len() {
                let vals: Vec<String> = blinding_round_ood_ans[r]
                    .iter()
                    .map(|f| format!("\"{}\"", field_str(f)))
                    .collect();
                writeln!(out, "  [{}]{comma}", vals.join(", "))?;
            } else {
                writeln!(out, "  [\"0\"]{comma}")?;
            }
        }
        writeln!(out, "]")?;

        writeln!(out, "blinding_round_sumcheck_coeffs = [")?;
        for r in 0..blinding_round_array_size {
            write!(out, "  [")?;
            if r < blinding_round_sumcheck_coeffs_vec.len() {
                let coeffs = &blinding_round_sumcheck_coeffs_vec[r];
                for i in 0..blinding_ff {
                    if i < coeffs.len() {
                        let c = coeffs[i];
                        let comma = if i < blinding_ff - 1 { ", " } else { "" };
                        write!(out, "[\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
                    } else {
                        let comma = if i < blinding_ff - 1 { ", " } else { "" };
                        write!(out, "[\"0\", \"0\"]{comma}")?;
                    }
                }
            } else {
                for i in 0..blinding_ff {
                    let comma = if i < blinding_ff - 1 { ", " } else { "" };
                    write!(out, "[\"0\", \"0\"]{comma}")?;
                }
            }
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;

        writeln!(
            out,
            "blinding_round_pow_nonces = [{}]",
            (0..blinding_round_array_size)
                .map(|r| {
                    if r < blinding_round_pow_nonce_vec.len() {
                        blinding_round_pow_nonce_vec[r].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "blinding_round_num_queries = [{}]",
            (0..blinding_round_array_size)
                .map(|r| {
                    if r < merkle.blinding_round.len() {
                        merkle.blinding_round[r].indices.len().to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out, "blinding_round_merkle_leaves = [")?;
        for r in 0..blinding_round_array_size {
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            write!(out, "  [")?;
            for q in 0..blinding_queries {
                let q_comma = if q < blinding_queries - 1 { ", " } else { "" };
                if r < merkle.blinding_round.len() && q < merkle.blinding_round[r].leaves.len() {
                    let mut vals = merkle.blinding_round[r].leaves[q]
                        .iter()
                        .map(|f| format!("\"{}\"", field_str(f)))
                        .collect::<Vec<_>>();
                    vals.extend(std::iter::repeat_n(
                        "\"0\"".to_string(),
                        expected_blinding_leaf_size.saturating_sub(vals.len()),
                    ));
                    write!(out, "[{}]{q_comma}", vals.join(", "))?;
                } else {
                    write!(
                        out,
                        "[{}]{q_comma}",
                        vec!["\"0\""; expected_blinding_leaf_size].join(", ")
                    )?;
                }
            }
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;
        writeln!(out, "blinding_round_merkle_siblings = [")?;
        for r in 0..blinding_round_array_size {
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            write!(out, "  [")?;
            for q in 0..blinding_queries {
                let q_comma = if q < blinding_queries - 1 { ", " } else { "" };
                if r < merkle.blinding_round.len() && q < merkle.blinding_round[r].siblings.len() {
                    let sibs = (0..blinding_tree_height)
                        .map(|h| {
                            if h < merkle.blinding_round[r].siblings[q].len() {
                                hash_field_str(&merkle.blinding_round[r].siblings[q][h])
                            } else {
                                "\"0\"".to_string()
                            }
                        })
                        .collect::<Vec<_>>();
                    write!(out, "[{}]{q_comma}", sibs.join(", "))?;
                } else {
                    write!(
                        out,
                        "[{}]{q_comma}",
                        vec!["\"0\""; blinding_tree_height].join(", ")
                    )?;
                }
            }
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;
        writeln!(out, "blinding_round_merkle_indices = [")?;
        for r in 0..blinding_round_array_size {
            let comma = if r < blinding_round_array_size - 1 { "," } else { "" };
            let row = (0..blinding_queries)
                .map(|q| {
                    if r < merkle.blinding_round.len()
                        && q < merkle.blinding_round[r].indices.len()
                    {
                        merkle.blinding_round[r].indices[q].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>();
            writeln!(out, "  [{}]{comma}", row.join(", "))?;
        }
        writeln!(out, "]")?;
        writeln!(
            out,
            "blinding_round_merkle_leaf_sizes = [{}]",
            (0..blinding_round_array_size)
                .map(|r| {
                    if r < merkle.blinding_round.len() {
                        merkle.blinding_round[r].leaf_size.to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "blinding_round_merkle_tree_heights = [{}]",
            (0..blinding_round_array_size)
                .map(|r| {
                    if r < merkle.blinding_round.len() {
                        merkle.blinding_round[r].height.to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out)?;

        // Blinding final Merkle proofs
        writeln!(out, "# Blinding final Merkle proofs")?;
        writeln!(
            out,
            "blinding_final_merkle_leaves = [{}]",
            (0..blinding_queries)
                .map(|q| {
                    if q < merkle.blinding_final.leaves.len() {
                        let mut vals = merkle.blinding_final.leaves[q]
                            .iter()
                            .map(|f| format!("\"{}\"", field_str(f)))
                            .collect::<Vec<_>>();
                        vals.extend(std::iter::repeat_n(
                            "\"0\"".to_string(),
                            expected_blinding_leaf_size.saturating_sub(vals.len()),
                        ));
                        format!("[{}]", vals.join(", "))
                    } else {
                        format!("[{}]", vec!["\"0\""; expected_blinding_leaf_size].join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "blinding_final_merkle_siblings = [{}]",
            (0..blinding_queries)
                .map(|q| {
                    let sibs = (0..blinding_tree_height)
                        .map(|h| {
                            if q < merkle.blinding_final.siblings.len()
                                && h < merkle.blinding_final.siblings[q].len()
                            {
                                hash_field_str(&merkle.blinding_final.siblings[q][h])
                            } else {
                                "\"0\"".to_string()
                            }
                        })
                        .collect::<Vec<_>>();
                    format!("[{}]", sibs.join(", "))
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "blinding_final_merkle_indices = [{}]",
            (0..blinding_queries)
                .map(|q| {
                    if q < merkle.blinding_final.indices.len() {
                        merkle.blinding_final.indices[q].to_string()
                    } else {
                        "0".to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "blinding_final_merkle_leaf_size = {}",
            merkle.blinding_final.leaf_size
        )?;
        writeln!(
            out,
            "blinding_final_merkle_tree_height = {}",
            merkle.blinding_final.height
        )?;
        writeln!(out)?;

        // === R1CS matrices ===
        writeln!(out, "# --- Phase 5: R1CS matrices ---")?;
        write_matrix_cells(&mut out, "matrix_a", &a_cells)?;
        write_matrix_cells(&mut out, "matrix_b", &b_cells)?;
        write_matrix_cells(&mut out, "matrix_c", &c_cells)?;

        let mut toml_file =
            File::create(&self.output_path).context("while creating Prover.toml")?;
        toml_file
            .write_all(out.as_bytes())
            .context("while writing Prover.toml")?;

        info!(
            toml_path = %self.output_path,
            json_path = %self.json_path,
            "Noir verifier inputs generated"
        );

        Ok(())
    }
}

fn write_byte_array(out: &mut String, name: &str, bytes: &[u8]) -> std::fmt::Result {
    write!(out, "{name} = [")?;
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{b}")?;
    }
    writeln!(out, "]")
}

fn write_field_array(out: &mut String, name: &str, fields: &[FieldElement]) -> std::fmt::Result {
    write!(out, "{name} = [")?;
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "\"{}\"", field_str(f))?;
    }
    writeln!(out, "]")
}

fn write_matrix_cells(
    out: &mut String,
    prefix: &str,
    cells: &[(u32, u32, FieldElement)],
) -> std::fmt::Result {
    write!(out, "{prefix}_rows = [")?;
    for (i, (r, _, _)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{r}")?;
    }
    writeln!(out, "]")?;

    write!(out, "{prefix}_cols = [")?;
    for (i, (_, c, _)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{c}")?;
    }
    writeln!(out, "]")?;

    write!(out, "{prefix}_vals = [")?;
    for (i, (_, _, v)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "\"{}\"", field_str(v))?;
    }
    writeln!(out, "]")?;

    writeln!(out, "{}_len = {}", prefix.replace("matrix_", ""), cells.len())
}

fn replace_u32_const(contents: &mut String, name: &str, value: u32) -> Result<()> {
    let needle = format!("pub global {name}: u32 = ");
    let start = contents
        .find(&needle)
        .with_context(|| format!("Could not find constant {name} in types.nr"))?;
    let after = &contents[start..];
    let semi_rel = after
        .find(';')
        .with_context(|| format!("Malformed constant line for {name} in types.nr"))?;
    let value_start = start + needle.len();
    let value_end = start + semi_rel;
    contents.replace_range(value_start..value_end, &value.to_string());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sync_types_file(
    path: &str,
    log_num_constraints: u32,
    log_num_variables: u32,
    num_whir_rounds: u32,
    folding_factor: u32,
    max_queries_per_round: u32,
    tree_height: u32,
    ood_samples: u32,
    log_inv_rate: u32,
    pow_bits: u32,
    max_public_inputs: u32,
    max_matrix_cells: u32,
    num_challenges: u32,
    w1_size: u32,
    batch_size: u32,
    blinding_ood_samples: u32,
    blinding_whir_rounds: u32,
    blinding_tree_height: u32,
    num_blinding_vectors: u32,
    num_witness_variables: u32,
    blinding_max_queries: u32,
    num_linear_forms: u32,
    num_w_folded_evals: u32,
    final_poly_size: u32,
    blinding_final_poly_size: u32,
    final_sumcheck_rounds: u32,
    blinding_final_sumcheck_rounds: u32,
    max_gammas: u32,
) -> Result<()> {
    let mut contents = fs::read_to_string(path)
        .with_context(|| format!("while reading types file at {path}"))?;

    replace_u32_const(&mut contents, "LOG_NUM_CONSTRAINTS", log_num_constraints)?;
    replace_u32_const(&mut contents, "LOG_NUM_VARIABLES", log_num_variables)?;
    replace_u32_const(&mut contents, "NUM_WHIR_ROUNDS", num_whir_rounds)?;
    replace_u32_const(&mut contents, "FOLDING_FACTOR", folding_factor)?;
    replace_u32_const(&mut contents, "MAX_QUERIES_PER_ROUND", max_queries_per_round)?;
    replace_u32_const(&mut contents, "TREE_HEIGHT", tree_height)?;
    replace_u32_const(&mut contents, "OOD_SAMPLES", ood_samples)?;
    replace_u32_const(&mut contents, "LOG_INV_RATE", log_inv_rate)?;
    replace_u32_const(&mut contents, "POW_BITS", pow_bits)?;
    replace_u32_const(&mut contents, "MAX_PUBLIC_INPUTS", max_public_inputs)?;
    replace_u32_const(&mut contents, "MAX_MATRIX_CELLS", max_matrix_cells)?;
    replace_u32_const(&mut contents, "NUM_CHALLENGES", num_challenges)?;
    replace_u32_const(&mut contents, "W1_SIZE", w1_size)?;
    replace_u32_const(&mut contents, "BATCH_SIZE", batch_size)?;
    replace_u32_const(&mut contents, "BLINDING_OOD_SAMPLES", blinding_ood_samples)?;
    replace_u32_const(&mut contents, "BLINDING_WHIR_ROUNDS", blinding_whir_rounds)?;
    replace_u32_const(&mut contents, "BLINDING_TREE_HEIGHT", blinding_tree_height)?;
    replace_u32_const(&mut contents, "NUM_BLINDING_VECTORS", num_blinding_vectors)?;
    replace_u32_const(&mut contents, "NUM_WITNESS_VARIABLES", num_witness_variables)?;
    replace_u32_const(&mut contents, "BLINDING_MAX_QUERIES", blinding_max_queries)?;
    replace_u32_const(&mut contents, "BLINDING_FOLD_SIZE", 1u32 << folding_factor)?;
    replace_u32_const(&mut contents, "NUM_LINEAR_FORMS", num_linear_forms)?;
    replace_u32_const(&mut contents, "NUM_W_FOLDED_EVALS", num_w_folded_evals)?;
    replace_u32_const(&mut contents, "FINAL_POLY_SIZE", final_poly_size)?;
    replace_u32_const(
        &mut contents,
        "BLINDING_FINAL_POLY_SIZE",
        blinding_final_poly_size,
    )?;
    replace_u32_const(&mut contents, "FINAL_SUMCHECK_ROUNDS", final_sumcheck_rounds)?;
    replace_u32_const(
        &mut contents,
        "BLINDING_FINAL_SUMCHECK_ROUNDS",
        blinding_final_sumcheck_rounds,
    )?;
    replace_u32_const(&mut contents, "MAX_GAMMAS", max_gammas)?;
    replace_u32_const(&mut contents, "FOLD_SIZE", 1u32 << folding_factor)?;
    replace_u32_const(&mut contents, "INTERLEAVING_DEPTH", 1u32 << folding_factor)?;
    replace_u32_const(
        &mut contents,
        "INNER_WHIR_CONSTRAINT_COUNT",
        ood_samples + num_linear_forms,
    )?;
    replace_u32_const(
        &mut contents,
        "BLINDING_WHIR_CONSTRAINT_COUNT",
        blinding_ood_samples + num_linear_forms,
    )?;
    replace_u32_const(
        &mut contents,
        "MAX_STIR_BYTES",
        std::cmp::max(
            max_queries_per_round * ((tree_height + 7) / 8),
            blinding_max_queries * ((blinding_tree_height + 7) / 8),
        ),
    )?;

    fs::write(path, contents).with_context(|| format!("while writing types file at {path}"))?;
    Ok(())
}
