# Praxis 100-bit Witness Encryption + ProveKit Demo (`direct` / `kzg`)

A working, end-to-end pure-Rust implementation of **Praxis** (_Praxis: Practical Witness Encryption for NP_, [ePrint 2026/2971](https://eprint.iacr.org/2026/2971) by David Tse, Nikhil Vanjani, and Psi Vesely) wired into **ProveKit** with two explicit architectures selected via `--mode`:

1. **`--mode direct`** (`src/direct.rs`): Noir → ProveKit `R1CS<Fr>` → Praxis `Bqs` → 100-bit Praxis WE.
   - Best for tiny, challenge-free circuits (e.g., [`noir-examples/praxis-satoshi`](../../noir-examples/praxis-satoshi/src/main.nr), ~36 MiB ciphertext).
2. **`--mode kzg`** (`src/kzg/`): Noir → ProveKit **2-Round Spartan + HyperKZG** (pure-Rust BN254, universal Powers-of-Tau SRS, **2 pairings**, zero Groth16 / zero Go/gnark) → Praxis WE.
   - Handles **arbitrary multi-challenge ProveKit circuits** (`w1 → Challenge → w2`, LogUp / Spice / SHA-256 spread tables), including all passport age-check circuits (`t_attest`, `t_add_*`, `complete_age_check`).
   - Keeps the full succinct verifier's 100-bit Praxis ciphertext at **~7.1–9.9 GiB** (comparable to the paper's 7.88 GiB Groth16 benchmark) instead of 100 GiB–4.75 TiB under direct BQS!

> **Note:** Research/demo prototype for experimentation and benchmarking, not audited production cryptography.

---

## Measured Benchmarks (16-core Apple Silicon, `--profile release-fast`)

Single shared universal BN254 KZG SRS ($2^{20} = 1{,}048{,}576$ $\mathbb{G}_1$ points) generated in **371.75 ms**:

| Circuit | Direct BQS CT | Spartan+HyperKZG Prove | Verify | Proof Size | Pairings | Succinct Verifier BQS $N$ | KZG → Praxis CT |
|---|---:|---:|---:|---:|---:|---:|---:|
| `praxis-satoshi` (0 challenges) | 20.6 MiB | 6.59 ms | 1.83 ms | 2.25 KiB | **2** | 352,356 | **7.11 GiB** |
| `t_attest` (Merkle + age, 7 challenges) | 99.8 GiB | 116.33 ms | 8.74 ms | 8.38 KiB | **2** | 443,910 | **8.95 GiB** |
| `t_add_integrity_commit` (29 challenges) | 812.2 GiB | 414.94 ms | 18.88 ms | 9.94 KiB | **2** | 466,362 | **9.40 GiB** |
| `t_add_id_data_720` (24 challenges) | 1.04 TiB | 583.01 ms | 22.57 ms | 10.28 KiB | **2** | 472,756 | **9.53 GiB** |
| `t_add_dsc_720` (22 challenges) | 2.43 TiB | 1.21 s | 43.00 ms | 11.06 KiB | **2** | 483,982 | **9.76 GiB** |
| `complete_age_check` (47 challenges, 1.1M w) | 4.75 TiB | **2.07 s** | **82.45 ms** | **11.62 KiB** | **2** | 492,792 | **9.93 GiB** |
| _Reference: Groth16 (Praxis paper §6.1)_ | — | — | — | 0.19 KiB | 3 | 391,693 | _7.88 GiB_ |

---

## Quick Start

Run everything from the ProveKit repository root:

```bash
# 1. Run all unit tests (univariate KZG, HyperKZG, Spartan+HyperKZG, Praxis core)
cargo test -p praxis-demo --profile release-fast

# 2. Direct mode on praxis-satoshi (~36 MiB 100-bit Praxis WE)
cargo run -p praxis-demo --profile release-fast -- --mode direct

# 3. KZG mode on praxis-satoshi (Spartan + HyperKZG -> 100-bit Praxis WE)
cargo run -p praxis-demo --profile release-fast -- --mode kzg --name satoshi --message "Passport KZG WE works!"

# 4. KZG mode on monolithic passport complete_age_check (1.1M witnesses, 47 challenges!)
cargo run -p praxis-demo --profile release-fast -- \
  --mode kzg \
  -c noir-examples/noir-passport-monolithic/complete_age_check \
  -i noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml \
  --message "Passport 18+ unlocked!"

# 5. Full passport suite benchmark (Direct vs Spartan+HyperKZG vs Groth16)
cargo run -p praxis-demo --example estimate_passport --profile release-fast
```

### CLI Options

| Flag            | Default                           | Description                                                         |
| --------------- | --------------------------------- | ------------------------------------------------------------------- |
| `-M, --mode`    | `direct`                          | Architecture mode: `direct` (R1CS → BQS) or `kzg` (Spartan+HyperKZG) |
| `-c, --circuit` | `noir-examples/praxis-satoshi`    | Noir circuit directory or compiled `.json` artifact                 |
| `-i, --input`   | `<circuit>/Prover.toml`           | Path to Noir `Prover.toml` input file                               |
| `-m, --message` | `"Hello from Praxis 100-bit WE!"` | Secret UTF-8 message to encrypt (max 32 bytes)                      |
| `-n, --name`    | _(none)_                          | Override 7-byte ASCII name for `praxis-satoshi` (`satoshi`, `vitalik`, …) |

---

## Architecture (`direct` vs `kzg`)

```text
tooling/praxis-demo/src/
├── lib.rs              # Shared library root & Noir loader/compiler
├── main.rs             # CLI dispatching `--mode direct` vs `--mode kzg`
├── direct.rs           # Direct path: Noir -> R1CS -> BQS -> Praxis 100-bit WE
├── kzg/
│   ├── mod.rs          # KZG path CLI runner (Spartan+HyperKZG -> Praxis WE)
│   ├── univariate.rs   # BN254 universal Powers-of-Tau KZG (commit, Ruffini open, 2-pairing batch verify)
│   ├── hyperkzg.rs     # HyperKZG multilinear PCS (LSB folding -> 3 univariate claims -> 2 pairings)
│   ├── spartan.rs      # 2-round Spartan + HyperKZG over ProveKit R1CS (`w1 -> Challenge -> w2`)
│   └── bqs_cost.rs     # Exact succinct verifier BQS cost model + executable algebraic-core BQS
├── bqs.rs              # Boolean Quadratic System & ProveKit R1CS -> BQS expander
├── ext.rs              # H_seed ring forms, F_{q^n} weights U/V, tie masks & cancellations
├── params.rs           # Praxis Table 4 100-bit security parameters on BN254
├── praxis.rs           # Praxis Setup / Enc / Dec & 12-bit signed-window fixed-base tables
├── qap.rs              # Coset-FFT QAP setup, barycentric eval & witness polynomials
└── search.rs           # Parallel G_T BSGS via degree-12 palindromic F_p recurrence
```
