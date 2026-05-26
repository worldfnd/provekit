//! `export-solidity` — turn a `provekit_groth16::VerifyingKey` (carried inside
//! a `.pkv`) into a concrete `ProvekitGroth16Verifier.sol` by substituting all
//! `CODEGEN` markers in the contract template with real BN254 constants.
//!
//! Outputs a contract that's directly compilable with `solc 0.8.20+` and
//! `forge build`. See `provekit/groth16/contracts/README.md` for the round-trip
//! test recipe (prove off-chain → dump bytes → `verifyProof` from forge).
//!
//! The Rust verifier (`provekit_groth16::verifier::verify`) is the
//! authoritative spec; the on-chain verifier must produce the same Pedersen
//! check, the same BSB22 challenge, and the same Groth16 pairing equation.
//! This tool exists so we never substitute constants by hand.

use {
    super::{util::resolve_key_path, Command},
    anyhow::{bail, ensure, Context, Result},
    argh::FromArgs,
    ark_bn254::{Fq, G1Affine, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{BigInteger, PrimeField},
    provekit_common::{file::read, Verifier},
    provekit_groth16::{VerifierGroth16Ext, VerifyingKey},
    std::{fmt::Write as _, fs, path::PathBuf},
    tracing::{info, instrument},
};

/// Generate a circuit-specific Solidity verifier from a `.pkv` file.
///
/// Reads the Groth16 verifying key embedded in `--pkv`, computes the
/// gnark-style negations (`-β`, `-γ`, `-δ`, `-σ·G`), and substitutes every
/// `CODEGEN` placeholder in the template at `--template`. Writes the result
/// to `--out`.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "export-solidity")]
pub struct Args {
    /// path to the ProveKit Verifier (PKV) file containing the Groth16
    /// verifying key (default: `<circuit>.pkv` in the current directory)
    #[argh(option, long = "pkv", short = 'v')]
    pkv_path: Option<PathBuf>,

    /// path to the Solidity template (typically
    /// `provekit/groth16/contracts/ProvekitGroth16Verifier.sol`)
    #[argh(option, long = "template", short = 't')]
    template_path: PathBuf,

    /// output path for the generated Solidity file
    #[argh(option, long = "out", short = 'o')]
    output_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let pkv_path = resolve_key_path(self.pkv_path.as_deref(), "pkv")?;
        let verifier: Verifier =
            read(&pkv_path).with_context(|| format!("reading {}", pkv_path.display()))?;

        // `groth16_vk_typed` runs `deserialize_uncompressed` which in turn
        // runs `precompute()` inline, so `g2_delta_neg`, `g2_gamma_neg`,
        // `e_alpha_beta` are filled in.
        let vk = verifier.groth16_vk_typed()?.context(
            "PKV does not contain a Groth16 verifying key (this PKV was built for the WHIR \
             backend, not Groth16)",
        )?;

        let params = CircuitParams::from_vk(&vk)?;
        info!(
            n_pub = params.n_pub,
            n_commit = params.n_commit,
            n_challenge_per_commit = params.n_challenge_per_commit,
            n_pub_extended = params.n_pub_extended,
            n_committed = params.n_committed,
            "loaded VK",
        );

        let template = fs::read_to_string(&self.template_path)
            .with_context(|| format!("reading template {}", self.template_path.display()))?;
        let rendered = render(&template, &vk, &params)?;

        if let Some(parent) = self.output_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(&self.output_path, rendered)
            .with_context(|| format!("writing {}", self.output_path.display()))?;

        info!(out = %self.output_path.display(), "wrote Solidity verifier");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Circuit dimensions
// ---------------------------------------------------------------------------

/// Compile-time-constant dimensions extracted from the VK.
///
/// Mirrors the constants at the top of `ProvekitGroth16Verifier.sol`. We
/// derive them here rather than asking the user to pass them on the command
/// line so the contract and prover can never disagree on shape.
struct CircuitParams {
    /// Number of explicit public inputs the circuit takes (excluding ONE_WIRE
    /// and derived BSB22 challenge wires).
    n_pub:                    usize,
    /// Number of BSB22 Pedersen commitments. Template only supports 1.
    n_commit:                 usize,
    /// Number of derived challenges per commitment. Template only supports 1.
    n_challenge_per_commit:   usize,
    /// `N_PUB + N_COMMIT * N_CHALLENGE`.
    n_pub_extended:           usize,
    /// Number of `input[]` entries hashed into the BSB22 challenge — the
    /// length of `vk.public_and_commitment_committed[0]`.
    n_committed:              usize,
    /// 0-indexed `input[]` indices in the order the prover hashes them.
    committed_idx_zero_based: Vec<usize>,
}

impl CircuitParams {
    fn from_vk(vk: &VerifyingKey) -> Result<Self> {
        let n_commit = vk.commitment_keys.len();
        ensure!(
            n_commit == 1,
            "this codegen template only supports single-commitment circuits (got N_COMMIT = \
             {n_commit}); multi-commitment support is listed as future work in the contract footer",
        );
        let n_challenge_per_commit = vk.num_challenges_per_commitment[0];
        ensure!(
            n_challenge_per_commit >= 1,
            "VK declares zero challenges for commitment 0 — single-commitment BSB22 needs at \
             least one",
        );

        let total_challenges: usize = vk.num_challenges_per_commitment.iter().sum();
        ensure!(
            vk.g1_k.len() >= total_challenges + 1,
            "invalid VK: g1_k has {} entries but {} challenges + ONE_WIRE declared",
            vk.g1_k.len(),
            total_challenges,
        );
        let n_pub = vk
            .g1_k
            .len()
            .checked_sub(total_challenges + 1)
            .context("g1_k smaller than ONE_WIRE + challenge wires")?;
        let n_pub_extended = n_pub + n_commit * n_challenge_per_commit;

        // `public_and_commitment_committed[i]` indices are 1-based offsets
        // into `extended_public` — see `verifier.rs:81-92`. By commitment i's
        // turn `extended_public` has length
        //   n_pub + Σ_{j<i} num_challenges_per_commitment[j]
        // and the loop body reads `extended_public[idx - 1]`. Under the
        // single-commitment guard above (i == 0), `extended_public` is just
        // `public_witness`, so the valid range collapses to 1..=n_pub and
        // each `idx - 1` is the 0-based offset into Solidity's `input[]`.
        //
        // If the n_commit==1 guard is ever lifted, this conversion must
        // also handle i>0 — where committed indices may reference earlier
        // commitments' derived challenges and the upper bound rises to
        // n_pub_extended.
        let raw = &vk.public_and_commitment_committed[0];
        let mut committed_idx_zero_based = Vec::with_capacity(raw.len());
        for &abs in raw {
            ensure!(
                abs >= 1 && abs <= n_pub,
                "commitment-committed index {abs} out of range (expected 1..={n_pub} for N_PUB = \
                 {n_pub})",
            );
            committed_idx_zero_based.push(abs - 1);
        }

        Ok(Self {
            n_pub,
            n_commit,
            n_challenge_per_commit,
            n_pub_extended,
            n_committed: raw.len(),
            committed_idx_zero_based,
        })
    }
}

// ---------------------------------------------------------------------------
// Hex / coordinate helpers
// ---------------------------------------------------------------------------

/// Format a BN254 base-field element as a 32-byte big-endian `0xHEX` string,
/// matching how the Solidity contract reads coordinates from calldata.
fn fp_hex(f: &Fq) -> String {
    let mut bytes = f.into_bigint().to_bytes_be();
    // `into_bigint().to_bytes_be()` returns a full-limb-width buffer (32B for
    // BN254 Fq), but be defensive in case arkworks tweaks the layout.
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(&bytes);
        bytes = padded;
    }
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for b in &bytes[bytes.len() - 32..] {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

/// Solidity-compatible representation of a G1 point: just `(x_hex, y_hex)`.
/// Panics if called on the point at infinity — the VK shouldn't contain any.
fn g1_coords(p: &G1Affine, name: &str) -> Result<(String, String)> {
    let (x, y) = p
        .xy()
        .with_context(|| format!("{name} is the point at infinity in the VK"))?;
    Ok((fp_hex(&x), fp_hex(&y)))
}

/// Solidity-compatible representation of a G2 point in EIP-197 ordering:
/// `(x.c0, x.c1, y.c0, y.c1)`. Note: the on-chain pairing precompile expects
/// the c1 component before c0 — that ordering is applied in the contract
/// itself (`pairings[2] = bsX1; pairings[3] = bsX0; …`), so we emit the
/// natural (c0, c1, c0, c1) here.
fn g2_coords(p: &G2Affine, name: &str) -> Result<(String, String, String, String)> {
    let (x, y) = p
        .xy()
        .with_context(|| format!("{name} is the point at infinity in the VK"))?;
    Ok((fp_hex(&x.c0), fp_hex(&x.c1), fp_hex(&y.c0), fp_hex(&y.c1)))
}

/// Negate a G2 point in projective space, returning the affine form.
fn g2_neg(p: &G2Affine) -> G2Affine {
    (-G2Projective::from(*p)).into_affine()
}

// ---------------------------------------------------------------------------
// Template substitution
// ---------------------------------------------------------------------------

fn render(template: &str, vk: &VerifyingKey, params: &CircuitParams) -> Result<String> {
    let mut out = template.to_string();

    // ---------- scalar constants ----------
    // Mapping of `uint256 internal constant NAME` → value (decimal or 0x hex).
    let (alpha_x, alpha_y) = g1_coords(&vk.g1_alpha, "vk.g1_alpha")?;
    let g2_beta_neg = g2_neg(&vk.g2_beta);
    let (beta_x0, beta_x1, beta_y0, beta_y1) = g2_coords(&g2_beta_neg, "-vk.g2_beta")?;
    let (gamma_x0, gamma_x1, gamma_y0, gamma_y1) = g2_coords(&vk.g2_gamma_neg, "vk.g2_gamma_neg")?;
    let (delta_x0, delta_x1, delta_y0, delta_y1) = g2_coords(&vk.g2_delta_neg, "vk.g2_delta_neg")?;
    let (k0_x, k0_y) = g1_coords(&vk.g1_k[0], "vk.g1_k[0]")?;

    let ck = &vk.commitment_keys[0];
    let (pg_x0, pg_x1, pg_y0, pg_y1) = g2_coords(&ck.g, "vk.commitment_keys[0].g")?;
    let (psn_x0, psn_x1, psn_y0, psn_y1) =
        g2_coords(&ck.g_sigma_neg, "vk.commitment_keys[0].g_sigma_neg")?;

    let scalar_subs: Vec<(&str, String)> = vec![
        // circuit dimensions
        ("N_PUB", params.n_pub.to_string()),
        ("N_COMMIT", params.n_commit.to_string()),
        ("N_CHALLENGE", params.n_challenge_per_commit.to_string()),
        ("N_PUB_EXTENDED", params.n_pub_extended.to_string()),
        ("N_COMMITTED", params.n_committed.to_string()),
        // VK constants (G1 + G2 + Pedersen)
        ("ALPHA_X", alpha_x),
        ("ALPHA_Y", alpha_y),
        ("BETA_NEG_X_0", beta_x0),
        ("BETA_NEG_X_1", beta_x1),
        ("BETA_NEG_Y_0", beta_y0),
        ("BETA_NEG_Y_1", beta_y1),
        ("GAMMA_NEG_X_0", gamma_x0),
        ("GAMMA_NEG_X_1", gamma_x1),
        ("GAMMA_NEG_Y_0", gamma_y0),
        ("GAMMA_NEG_Y_1", gamma_y1),
        ("DELTA_NEG_X_0", delta_x0),
        ("DELTA_NEG_X_1", delta_x1),
        ("DELTA_NEG_Y_0", delta_y0),
        ("DELTA_NEG_Y_1", delta_y1),
        ("K0_X", k0_x),
        ("K0_Y", k0_y),
        ("PEDERSEN_G_X_0", pg_x0),
        ("PEDERSEN_G_X_1", pg_x1),
        ("PEDERSEN_G_Y_0", pg_y0),
        ("PEDERSEN_G_Y_1", pg_y1),
        ("PEDERSEN_GSIGMA_NEG_X_0", psn_x0),
        ("PEDERSEN_GSIGMA_NEG_X_1", psn_x1),
        ("PEDERSEN_GSIGMA_NEG_Y_0", psn_y0),
        ("PEDERSEN_GSIGMA_NEG_Y_1", psn_y1),
    ];
    for (name, value) in &scalar_subs {
        out = replace_constant(&out, name, value)
            .with_context(|| format!("substituting constant {name}"))?;
    }

    // ---------- block replacements ----------
    out = replace_block(&out, "PUB_BASES", &render_pub_bases(vk, params)?)?;
    out = replace_block(&out, "MSM_STEPS", &render_msm_steps(params))?;
    out = replace_block(&out, "COMMITTED_INDICES", &render_committed_indices(params))?;

    // Any leftover `// CODEGEN` markers mean the template grew a new slot
    // this tool doesn't know about. Fail loud rather than ship a half-baked
    // verifier.
    if let Some(line) = out
        .lines()
        .find(|l| l.contains("CODEGEN") && !l.trim_start().starts_with("//"))
    {
        bail!("template still contains an unsubstituted CODEGEN marker: {line:?}");
    }

    Ok(out)
}

/// Replace the right-hand side of `uint256 internal constant NAME = ...;`
/// with `new_value`. Errors if the constant declaration is missing or
/// appears more than once.
fn replace_constant(src: &str, name: &str, new_value: &str) -> Result<String> {
    // We match the declaration line robustly across whitespace variations:
    //
    //     uint256 internal constant <NAME>[whitespace]=[whitespace]<old>;
    //
    // and rewrite it as
    //
    //     uint256 internal constant <NAME> = <new>;
    //
    // preserving the original indentation. Anything after the semicolon
    // (e.g. `// CODEGEN`) is preserved.
    let mut found = false;
    let mut output = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        if !found {
            if let Some(rewritten) = try_rewrite_constant_line(line, name, new_value) {
                output.push_str(&rewritten);
                found = true;
                continue;
            }
        }
        output.push_str(line);
    }
    ensure!(found, "no declaration of `{name}` found in template");
    // Defensive: refuse to substitute when the same constant appears twice.
    let occurrences = src.matches(&format!("constant {name} ")).count()
        + src.matches(&format!("constant {name}=")).count();
    ensure!(
        occurrences <= 1,
        "constant `{name}` appears {occurrences} times in template; codegen requires exactly one \
         declaration",
    );
    Ok(output)
}

fn try_rewrite_constant_line(line: &str, name: &str, new_value: &str) -> Option<String> {
    // Quick reject: the constant name must appear in the line surrounded by
    // word boundaries that match the `constant NAME` pattern.
    let needle = format!("constant {name}");
    let idx = line.find(&needle)?;
    // The next non-space char after the name must be `=` (allows `NAME=` or
    // `NAME =` etc.). Without this we'd happily rewrite `NAME_X` when asked
    // for `NAME`.
    let after_name = &line[idx + needle.len()..];
    let mut chars = after_name.chars();
    let next_significant = chars.by_ref().find(|c| !c.is_whitespace())?;
    if next_significant != '=' {
        return None;
    }

    // Split the line at the `=` and replace everything up to the next `;`.
    let eq_idx = line[idx + needle.len()..].find('=')? + idx + needle.len();
    let semi_idx = line[eq_idx..].find(';')? + eq_idx;
    // `let prefix = line[..eq_idx];  // includes "constant NAME"` part and the `=`.
    let prefix = &line[..eq_idx + 1]; // include '='

    // Build a clean suffix: `;` plus the line terminator, dropping any trailing
    // `// CODEGEN…` placeholder comment. Without this, the leftover-CODEGEN
    // detector in `render()` would fire on every successfully-substituted
    // line — `uint256 … = 0x…; // CODEGEN` contains "CODEGEN" but doesn't
    // start with "//" after `trim_start`. Dropping the comment also keeps the
    // detector useful as a tripwire for *unknown* CODEGEN slots a future
    // template grows.
    let raw_suffix = &line[semi_idx..]; // starts with ';'
    let suffix: String = match raw_suffix.find('\n') {
        Some(nl) => {
            let between = &raw_suffix[1..nl];
            if between.trim_start().starts_with("//") && between.contains("CODEGEN") {
                format!(";{}", &raw_suffix[nl..])
            } else {
                raw_suffix.to_string()
            }
        }
        None => {
            // No trailing newline (file's last line); same rule applied to the tail.
            let between = &raw_suffix[1..];
            if between.trim_start().starts_with("//") && between.contains("CODEGEN") {
                ";".to_string()
            } else {
                raw_suffix.to_string()
            }
        }
    };

    let mut rewritten = String::with_capacity(line.len() + new_value.len());
    rewritten.push_str(prefix.trim_end_matches('='));
    rewritten.push_str("= ");
    rewritten.push_str(new_value);
    rewritten.push_str(&suffix);
    Some(rewritten)
}

/// Replace the content between `//<BEGIN_CODEGEN:TAG>` and
/// `//<END_CODEGEN:TAG>` (exclusive of the markers themselves) with
/// `replacement`. Each replacement line is re-indented to match the
/// END marker line; the template always aligns BEGIN/END so this is
/// equivalent to "preserve the block's indent".
fn replace_block(src: &str, tag: &str, replacement: &str) -> Result<String> {
    let begin_marker = format!("//<BEGIN_CODEGEN:{tag}>");
    let end_marker = format!("//<END_CODEGEN:{tag}>");

    let begin = src
        .find(&begin_marker)
        .with_context(|| format!("missing `{begin_marker}` in template"))?;
    let after_begin_line_end = src[begin..]
        .find('\n')
        .map(|n| begin + n + 1)
        .with_context(|| format!("`{begin_marker}` not followed by a newline"))?;
    let end = src
        .find(&end_marker)
        .with_context(|| format!("missing `{end_marker}` in template"))?;
    ensure!(
        end > begin,
        "block markers for `{tag}` are in the wrong order"
    );
    // `end_line_start` points at the first byte of the END marker's line.
    // The slice `src[end_line_start..end]` is then just the leading
    // whitespace before `//<END_CODEGEN:…>`, which we reuse as the indent
    // for each generated line below.
    let end_line_start = src[..end].rfind('\n').map(|n| n + 1).unwrap_or(0);

    let indent = leading_whitespace(&src[end_line_start..end]);
    let mut indented = String::new();
    for body_line in replacement.lines() {
        if body_line.is_empty() {
            indented.push('\n');
        } else {
            indented.push_str(indent);
            indented.push_str(body_line);
            indented.push('\n');
        }
    }

    let mut out = String::with_capacity(src.len() + indented.len());
    out.push_str(&src[..after_begin_line_end]);
    out.push_str(&indented);
    out.push_str(&src[end_line_start..]);
    Ok(out)
}

fn leading_whitespace(s: &str) -> &str {
    let end = s
        .char_indices()
        .find(|(_, c)| !c.is_whitespace() || *c == '\n')
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

// ---------------------------------------------------------------------------
// Block renderers
// ---------------------------------------------------------------------------

fn render_pub_bases(vk: &VerifyingKey, params: &CircuitParams) -> Result<String> {
    ensure!(
        vk.g1_k.len() == params.n_pub_extended + 1,
        "VK g1_k length {} doesn't match N_PUB_EXTENDED + 1 = {}",
        vk.g1_k.len(),
        params.n_pub_extended + 1,
    );
    let mut s = String::new();
    for i in 0..params.n_pub_extended {
        let (x, y) = g1_coords(&vk.g1_k[i + 1], &format!("vk.g1_k[{}]", i + 1))?;
        let role = if i < params.n_pub {
            format!("public input #{i}")
        } else {
            format!("challenge #{}", i - params.n_pub)
        };
        writeln!(
            &mut s,
            "uint256 internal constant PUB_{i}_X = {x}; // K[{}] — {role}",
            i + 1
        )
        .unwrap();
        writeln!(
            &mut s,
            "uint256 internal constant PUB_{i}_Y = {y}; // K[{}] — {role}",
            i + 1
        )
        .unwrap();
    }
    Ok(s)
}

fn render_msm_steps(params: &CircuitParams) -> String {
    let mut s = String::new();
    // First N_PUB entries are public inputs from calldata.
    for i in 0..params.n_pub {
        writeln!(&mut s, "_msmStep(buf, PUB_{i}_X, PUB_{i}_Y, input[{i}]);").unwrap();
    }
    // Then the derived BSB22 challenges. The contract now always passes a
    // `uint256[N_CHALLENGE] memory challenges` array (size 1 when there's a
    // single challenge), so we always index it.
    for j in 0..(params.n_commit * params.n_challenge_per_commit) {
        let pub_idx = params.n_pub + j;
        writeln!(
            &mut s,
            "_msmStep(buf, PUB_{pub_idx}_X, PUB_{pub_idx}_Y, challenges[{j}]);"
        )
        .unwrap();
    }
    s
}

fn render_committed_indices(params: &CircuitParams) -> String {
    let mut s = String::new();
    for (slot, src_idx) in params.committed_idx_zero_based.iter().enumerate() {
        writeln!(
            &mut s,
            "_writeReversedAt(msgBuf, 64 + 32 * {slot}, input[{src_idx}]); // committed[{slot}] = \
             input[{src_idx}]"
        )
        .unwrap();
    }
    s
}
