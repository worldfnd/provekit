# CUDA NTT backend — benchmark notes

This document records how the CUDA backend (`provekit/common/src/ntt/backends/cuda/`)
was measured and what the numbers look like on the reference workstation. It mirrors
the existing Metal backend in structure, but on Linux + NVIDIA the matrix produced by
the encode kernel can stay on the GPU between commit and the WHIR open phase, which is
where most of the host-memory savings come from.

The CUDA backend implements `whir::protocols::irs_commit::IrsCommitter<Fr>` (in
`commit.rs`) so that:

1. `encode_matrix` runs on the GPU and leaves the encoded matrix in a pooled
   `CudaSlice<u8>` device buffer.
2. The Merkle leaf hashes are computed on the GPU (`encode_field_rows_le`
   + `sha256_many`).
3. The internal Merkle nodes are computed on the GPU layer-by-layer over a
   single tree buffer.
4. `DeviceRows::read_rows` and `DeviceMerkleWitness::read_nodes` lazily download
   only the rows / nodes WHIR actually opens.

When the workload is too small or the hash isn't SHA-2, the implementation falls
back cleanly to `CpuIrsCommitter` (same predicate as the Metal backend).

---

## Environment

| Component | Value |
|---|---|
| OS | Pop!_OS 24.04 LTS, Linux 6.18.7 (x86_64) |
| CPU | 12th Gen Intel Core i7-12700H (10 P+E cores, 20 threads) |
| RAM | 38 GiB |
| GPU | NVIDIA GeForce RTX 3060 Laptop, 6 GiB, compute capability 8.6 |
| Driver | 580.126.18 |
| CUDA toolkit | 12.0 (V12.0.140), `libnvrtc.so.12`, `libcuda.so.1` |
| Rust | nightly 2026-03-03 (1.96.0-nightly) |
| `cudarc` crate | 0.19.4 (`dynamic-loading` + `nvrtc`, no link-time CUDA dep) |
| ProveKit commit | `c2c969a5` (branch `zkfr/add-cuda-gpu`) |
| WHIR commit | `8742f70` ("feat: IRS commit") |

The `cudarc` dependency is feature-gated on `target_os = "linux"` and uses
`dynamic-loading`, so the binary has no compile-time link to the CUDA libraries —
it simply fails the `CudaBn254Ntt::new()` initialisation and falls back to CPU
when the libraries aren't available at runtime.

### Workload

The benchmarks below all use the same Noir circuit:

```
noir-examples/noir-passport-monolithic/complete_age_check
```

with `prover.pkp` prepared using SHA-2 leaf/Merkle hashes (the configuration the
GPU commit path requires). The prove command itself is:

```bash
cd noir-examples/noir-passport-monolithic/complete_age_check
target/release/provekit-cli prove ./prover.pkp ./Prover.toml
```

The same command is used for both modes; only the env var changes:

- **CPU baseline** — `PROVEKIT_DISABLE_CUDA_NTT=1` (forces the fallback path).
- **CUDA** — no env var; `CudaBn254Ntt::new()` initialises and registers as the
  `IrsCommitter<Fr>` for `Fr = ark_bn254::Fr`.

Other useful env vars:

- `PROVEKIT_CUDA_NTT_TRACE=1` — emit per-call backend events on stderr (init
  device, NTT roots-cache hits/misses, encode shapes, PTX cache hits).

### Build

```bash
cargo build --release --bin provekit-cli
```

The binary picks up CUDA automatically because the workspace `provekit-common`
dependency enables the `provekit_ntt` feature, and `lib.rs::build_irs_committer`
registers `Arc::new(CudaBn254Ntt)` directly as the IRS committer on Linux when
init succeeds.

### Parity tests

Three tests compare the GPU output to the CPU reference:

```bash
cargo test --release -p provekit-common --features provekit_ntt \
  --lib ntt::cuda_tests -- --test-threads=1
```

```
running 3 tests
test ntt::cuda_tests::cuda_matches_cpu_for_large_case ... ok
test ntt::cuda_tests::cuda_matches_cpu_for_multi_poly_case ... ok
test ntt::cuda_tests::cuda_matches_cpu_with_masks ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 72 filtered out
```

---

## Measurement methodology

Three measurement passes were used:

1. **OS-level wall / CPU / memory** via `/usr/bin/time -v`, 5 runs per mode
   (Python wrapper to compute mean ± stdev of each field).
2. **Per-process peak GPU memory** via `nvidia-smi --query-compute-apps`
   sampled every 50 ms during a single CUDA prove.
3. **Per-shape commit timings** parsed from the prover's own
   `tracing_flame`-style hierarchical logs; each `whir::irs_commit::commit`
   span is paired with its closing duration line and decomposed into
   "encode" (`gpu_encode` / `encode_matrix` for CUDA, `interleaved_encode`
   for CPU) vs "rest" (leaf hash + Merkle tree).

All three Python scripts are reproduced verbatim below so the numbers are
re-measurable exactly.

---

## 1. OS-level stats — `/usr/bin/time -v`

### Command

5 runs per mode through the same Python wrapper. The wrapper was invoked from the
prover example directory:

```python
import os, re, subprocess, statistics

BIN = "/home/zkfriendly/dev/prove/provekit/target/release/provekit-cli"
ARGS = ["prove", "./prover.pkp", "./Prover.toml"]

def one_run(env_extra):
    env = dict(os.environ); env.update(env_extra)
    p = subprocess.run(["/usr/bin/time", "-v", BIN, *ARGS],
                       env=env, capture_output=True)
    err = p.stderr.decode(errors='ignore')
    grab = lambda pat, conv=float: (lambda m: conv(m.group(1)) if m else None)(re.search(pat, err))
    wall_str = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\S+)', err)
    parts = [float(x) for x in wall_str.group(1).split(':')] if wall_str else []
    wall = (parts[-1] + (parts[-2]*60 if len(parts)>=2 else 0)
            + (parts[-3]*3600 if len(parts)>=3 else 0)) if parts else None
    return dict(
        wall=wall,
        user=grab(r'User time \(seconds\):\s*([\d.]+)'),
        sys=grab(r'System time \(seconds\):\s*([\d.]+)'),
        cpu_pct=grab(r'Percent of CPU this job got:\s*(\d+)\s*%'),
        rss_mb=(grab(r'Maximum resident set size \(kbytes\):\s*(\d+)', int) or 0)/1024,
        minor_pf=grab(r'Minor \(reclaiming a frame\) page faults:\s*(\d+)', int),
        major_pf=grab(r'Major \(requiring I/O\) page faults:\s*(\d+)', int),
        vol_cs=grab(r'Voluntary context switches:\s*(\d+)', int),
        invol_cs=grab(r'Involuntary context switches:\s*(\d+)', int),
        exit=p.returncode,
    )

for label, env in [("CPU", {"PROVEKIT_DISABLE_CUDA_NTT":"1"}), ("CUDA", {})]:
    runs = [one_run(env) for _ in range(5)]
    for k in ("wall","user","sys","cpu_pct","rss_mb","minor_pf","major_pf","vol_cs","invol_cs"):
        vs = [r[k] for r in runs if r[k] is not None]
        m = statistics.mean(vs); s = statistics.stdev(vs) if len(vs)>1 else 0
        print(f"  {label:<6}{k:<14}: {m:.2f} ± {s:.2f}")
```

### Results (mean ± stdev, n=5)

| metric | CPU | CUDA | Δ |
|---|---:|---:|---|
| wall (s) | 3.60 ± 0.27 | 3.62 ± 0.20 | flat (within noise) |
| internal `run:` (s) | 3.59 ± 0.27 | 3.49 ± 0.20 | **−2.8 %** |
| user CPU (s) | 25.11 ± 3.62 | 21.24 ± 2.38 | **−15.4 %** |
| sys CPU (s) | 1.47 ± 0.30 | 1.67 ± 0.26 | +14 % (driver ioctls) |
| CPU utilization | 735 ± 62 % | 631 ± 52 % | **−104 pp** |
| **peak host RSS (MB)** | **920 ± 9** | **693 ± 10** | **−227 MB / −24.7 %** |
| minor page faults | 558 639 | 392 727 | −30 % |
| voluntary ctx switches | 17 924 | 14 750 | −17 % |
| major page faults | 0 | 0 | — |

**The headline numbers are peak host RSS (−25 %) and user CPU time (−15 %).**
Wall clock is flat because the WHIR pipeline contains CPU-bound stages (sumcheck,
fold ops, file decompression) that aren't accelerated, and the GPU work runs on a
separate stream that overlaps with those stages.

---

## 2. Peak GPU memory — `nvidia-smi`

### Command

```python
import subprocess, threading, time, os

BIN = "/home/zkfriendly/dev/prove/provekit/target/release/provekit-cli"
ARGS = ["prove", "./prover.pkp", "./Prover.toml"]

def baseline_used():
    out = subprocess.check_output(
        ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"]
    ).decode()
    return int(out.strip().splitlines()[0])

def proc_used():
    out = subprocess.check_output(
        ["nvidia-smi", "--query-compute-apps=pid,used_memory",
         "--format=csv,noheader,nounits"]
    ).decode().strip()
    return sum(int(line.split(',')[1].strip()) for line in out.splitlines() if line)

base = baseline_used()
print(f"baseline GPU used by other apps: {base} MiB")

peak_total = base; peak_proc = 0; done = threading.Event()
def sample():
    nonlocal_peak = {"t": peak_total, "p": peak_proc}
    while not done.is_set():
        nonlocal_peak["t"] = max(nonlocal_peak["t"], baseline_used())
        nonlocal_peak["p"] = max(nonlocal_peak["p"], proc_used())
        time.sleep(0.05)
    sample.result = nonlocal_peak

t = threading.Thread(target=sample); t.start()
subprocess.run([BIN, *ARGS], capture_output=True)
done.set(); t.join()
print(sample.result)
```

### Results

```
baseline GPU used by other apps: 1031 MiB   (cosmic-comp + Xwayland)
peak GPU total used:             1855 MiB
peak provekit-cli on GPU:        1032 MiB
```

So the prover itself peaks at **~1 GiB on the GPU**. This is two pooled
working buffers (`current` + `transposed`) for the largest commit
(1×1048576 vector → codeword length 524 288 × 8 messages = 4 M GpuFields = 128 MiB
each; rounded up to next pow-of-two by the bucket pool), plus the persistent
matrix and Merkle-tree buffers held alive by the active `IrsCommitArtifact`,
plus the NTT roots-of-unity cache. Comfortably inside the 6 GiB VRAM on the 3060.

### Net memory across host + device

| backend | host peak | GPU peak | combined |
|---|---:|---:|---:|
| CPU  | 920 MB | 0 MB | 920 MB |
| CUDA | 693 MB | 1032 MB | ~1.7 GB |

We trade ~227 MB of host RAM for ~1 GB of GPU RAM. That trade is the whole point
of `IrsCommitter`: the encoded matrix and Merkle tree never have to be
materialised on the host.

---

## 3. Commit-phase decomposition — parsed from the prover's tracing logs

### Capture command

```bash
cd noir-examples/noir-passport-monolithic/complete_age_check
PROVEKIT_DISABLE_CUDA_NTT=1 target/release/provekit-cli prove \
    ./prover.pkp ./Prover.toml > /tmp/prove_cpu.log  2>&1
target/release/provekit-cli prove \
    ./prover.pkp ./Prover.toml > /tmp/prove_cuda.log 2>&1
```

### Parser

The prover emits hierarchical spans like

```
├─╮ whir::protocols::irs_commit::commit self=size 1×1048576/8 rate 2⁻2.00 …
│ ├─╮ provekit_common::ntt::backends::cuda::encode::encode_matrix …
│ ├─╯ encode_matrix: 33.20 ms duration …
├─╯ commit: 52.35 ms duration …
```

The parser strips ANSI, pairs each `├─╮` opening line with its sibling `├─╯`
closing line at the same depth, and groups by the `size A×B` shape suffix.
For each parent commit it also locates the inner encode child to split
"encode" from "rest" (leaf-hash + Merkle-tree).

```python
import re

def parse(path):
    s = open(path, 'rb').read().decode(errors='ignore')
    return re.sub(r'\x1b\[[0-9;]*[mGKH]', '', s).splitlines()

def depth(line):
    head = line.split('├')[0] if '├' in line else line.split('╰')[0] if '╰' in line else line
    return head.count('│')

def to_ms(v, u):
    v = float(v)
    return v*1000 if u=='s' else (v/1000 if u=='μs' else (v/1e6 if u=='ns' else v))

DUR = re.compile(r'([0-9.]+)\s*(ms|μs|s|ns)\s*duration')

def commits(path):
    lines = parse(path)
    rows = []
    for i, line in enumerate(lines):
        if '├─╮' not in line: continue
        m = re.search(r'irs_commit::commit self=size (\d+×\d+)/\d+', line)
        if not m: continue
        d = depth(line); shape = m.group(1)
        # close at same depth
        close = next((j for j in range(i+1, len(lines))
                      if '├─╯' in lines[j] and depth(lines[j]) == d), None)
        if close is None: continue
        cm = DUR.search(lines[close])
        total_ms = to_ms(cm.group(1), cm.group(2)) if cm else None
        # find the inner encode child
        encode_ms, kind = None, None
        for j in range(i+1, close):
            cl = lines[j]
            if '├─╮' not in cl: continue
            if 'cuda::encode::encode_matrix' in cl: kind = 'gpu_encode'
            elif 'cpu::interleaved_encode'    in cl: kind = 'cpu_encode'
            else: continue
            cd = depth(cl)
            cclose = next((k for k in range(j+1, close+1)
                           if '├─╯' in lines[k] and depth(lines[k]) == cd), None)
            if cclose is not None:
                em = DUR.search(lines[cclose])
                if em: encode_ms = to_ms(em.group(1), em.group(2))
            break
        rows.append((shape, total_ms, encode_ms, kind))
    return rows
```

### Top-level commits per shape (mean of 2 calls each)

| shape (vec×size) | CPU total | CUDA total | speedup |
|---|---:|---:|---:|
| 1×1048576 *(GPU)* | 190.5 ms | **52.4 ms** | **3.6×** |
| 1×131072  *(GPU)* | 88.7 ms  | **22.4 ms** | **4.0×** |
| 1×16384   *(GPU)* | 36.0 ms  | **10.5 ms** | **3.4×** |
| 21×4096   *(GPU)* | 10.1 ms  | **5.8 ms**  | **1.7×** |
| 1×2048   *(CPU)*  | 15.0 ms  | 11.9 ms     | 1.3× (noise) |
| 1×256    *(CPU)*  | 5.4 ms   | 7.5 ms      | noise (both CPU) |
| 1×512 / 1×64 / 1×32 / 1×8 *(CPU)* | sub-ms each | sub-ms each | flat |
| **TOTAL (all 20 commits)** | **698 ms** | **227 ms** | **3.1× / −67 %** |

The four GPU-eligible shapes (≥ 2²⁰ elements **or** ≥ 64 rows, with the SHA-2
leaf/Merkle hash) account for nearly all the savings: 650 → 183 ms = −467 ms.
The smaller shapes correctly fall through to `CpuIrsCommitter` and show no
meaningful change (same `RSFr` encoder both ways).

### Inside each commit — encode vs hash + merkle

| shape | path | total ms | encode ms | rest (leaf-hash + merkle) ms |
|---|---|---:|---:|---:|
| 1×1048576 | CPU encode + CPU sha+merkle | 190.5 | 160.5 | 30.0 |
| 1×1048576 | **GPU encode + GPU sha+merkle** | **52.4** | **33.2** | **19.2** |
| 1×131072 | CPU | 88.7 | 74.9 | 13.8 |
| 1×131072 | **GPU** | **22.4** | **13.8** | **8.6** |
| 1×16384 | CPU | 36.0 | 28.6 | 7.4 |
| 1×16384 | **GPU** | **10.5** | **5.6** | **4.9** |
| 21×4096 | CPU | 10.1 | 7.6 | 2.6 |
| 21×4096 | **GPU** | **5.8** | **1.9** | 4.0 |

Per-row interpretation:

- **encode** drops by **~4–5×** on the four GPU shapes — the NTT kernel is
  the primary win.
- **hash + merkle** drops by **~1.5×**. CPU SHA-256 has hardware acceleration
  (`sha_ni`) on this Alder Lake part, so the GPU's per-byte SHA throughput
  edge over the CPU is much smaller than its NTT edge. The GPU still wins
  because (a) it overlaps with the encode on the same stream and (b) it
  avoids a 128 MB host download.
- For `21×4096` the "rest" cost actually rises slightly on GPU (4.0 vs 2.6
  ms): with 168 small rows the hash kernel and the per-Merkle-layer launch
  overhead start to dominate over the per-leaf savings. Still a net win on
  the commit total.

---

## Why wall-clock barely moves despite these wins

The GPU saves **471 ms of IRS-commit work** (698 → 227 ms) and **227 MB of host
memory**, but the prover's wall-clock barely changes (3.60 → 3.62 s). Two reasons:

1. The remainder of the prove pipeline — sumcheck rounds, the
   `fold_weight_to_mask_size` calls, `evaluate_gamma_block`, and the LZMA-
   compressed `.pkp` decompression — is unchanged and stays on the CPU. That
   accounts for ~3 seconds of the ~3.6 s wall.
2. The CUDA work runs on a separate CUDA stream and overlaps with those CPU
   stages, so the saved work shows up as **less host CPU time** and **less
   peak host RSS** rather than as a wall-clock drop.

The matrix-stays-on-device pattern (the `IrsCommitter` impl + `DeviceRows` /
`DeviceMerkleWitness`) is the key foundation for ever pulling additional
WHIR stages onto the GPU, since the matrix doesn't have to be marshalled
back across PCIe between phases.

---

## Cross-reference to the source layout

```
provekit/common/src/ntt/backends/cuda/
├── mod.rs        CudaBn254Ntt + ReedSolomon impl + new()/runtime() + GPU-shape filter
├── engine.rs     CudaRuntime: cudarc context, default stream, nvrtc compile + PTX
│                 disk cache (~/.cache/provekit/cuda), kernel handles, NTT roots
│                 cache, byte-level pooled buffer pool, raw memset/memcpy helpers
├── encode.rs     gpu_encode (returns Vec<Fr>) + encode_matrix (returns DeviceMatrix
│                 on device) + encode_shape — uploads &[Fr] directly via the
│                 layout-equivalent &[GpuField] view
├── commit.rs     IrsCommitter<Fr>, hash_rows_to_buffer, build_merkle_witness,
│                 DeviceRows: MatrixRows<Fr>, DeviceMerkleWitness: WitnessTrait
├── field.rs      Fr ↔ GpuField (4×u64 Montgomery limbs)
├── types.rs      GpuField + DeviceRepr/ValidAsZeroBits + param structs +
│                 DeviceMatrix / DeviceRows / DeviceMerkleWitness / EncodeShape
├── logging.rs    trace_event (PROVEKIT_CUDA_NTT_TRACE)
└── kernels/
    ├── common.cuh   Fe + struct layouts + BN254_MODULUS / N0PRIME / SHA256_K
    ├── field.cuh    Montgomery add/sub/mul + from_mont (port of metal/field.metal)
    ├── ntt.cu       bit_reverse_permute_rows_in_place, radix2_ntt_stage_rows_in_place,
    │                replicate_first_coset (port of metal/ntt.metal)
    ├── matrix.cu    transpose_matrix
    └── sha256.cu    encode_field_rows_le + sha256_many (port of metal/sha256.metal)
```

The CUDA backend is gated on `cfg(target_os = "linux")`. On macOS the Metal
backend (in `backends/metal/`) is selected by `lib.rs::build_irs_committer`;
on other platforms the CPU committer is used.
