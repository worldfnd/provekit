#!/usr/bin/env bash
# run_csp_benchmarks.sh
#
# Run prove/verify benchmarks for noir-examples/csp-benchmarks/* across the
# selected backends. Each circuit is compiled once; then for each backend
# `prepare` runs once and `prove` + `verify` are each invoked BENCH_RUNS
# times so the helper can average wall time, peak RSS, and heap-peak bytes
# (parsed from the prover's tracing output).
#
# Environment variables (all optional):
#   PROVEKIT_BIN         Path to provekit-cli (default: target/release/provekit-cli)
#   BENCH_ROOT           Path to csp-benchmarks (default: noir-examples/csp-benchmarks)
#   BENCH_DIR            Output directory (default: csp-bench-logs)
#   BENCH_RUNS           Iterations to average (default: 3)
#   BENCH_BACKENDS       Space-separated list of backends to benchmark
#                        (default: "whir groth16")
#   BENCH_SKIP_GROTH16   Regex of circuits to skip on the groth16 backend.
#                        Useful when a circuit's trusted-setup PK exceeds the
#                        runner's memory budget. Default empty (skip nothing).
#   TEST_FILTER          Regex on circuit name
#   MAX_TESTS            Cap on circuits (0 = unlimited)
#
# Output: BENCH_DIR/results.csv with one row per (circuit, backend):
#   circuit,backend,num_constraints,num_witnesses,prover_time_ms,
#     prover_peak_rss_kb,prover_heap_peak_bytes,verifier_time_ms,
#     proof_size_bytes,pkp_size_bytes,runs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELPER="${SCRIPT_DIR}/csp_benchmark_helpers.py"

PROVEKIT_BIN="${PROVEKIT_BIN:-${REPO_ROOT}/target/release/provekit-cli}"
BENCH_ROOT="${BENCH_ROOT:-${REPO_ROOT}/noir-examples/csp-benchmarks}"
BENCH_DIR="${BENCH_DIR:-${REPO_ROOT}/csp-bench-logs}"
BENCH_RUNS="${BENCH_RUNS:-3}"
BENCH_BACKENDS="${BENCH_BACKENDS:-whir groth16}"
BENCH_SKIP_GROTH16="${BENCH_SKIP_GROTH16:-}"
TEST_FILTER="${TEST_FILTER:-}"
MAX_TESTS="${MAX_TESTS:-0}"

if [[ "${BENCH_DIR}" != /* ]]; then
  BENCH_DIR="${REPO_ROOT}/${BENCH_DIR}"
fi

if [[ ! -x "${PROVEKIT_BIN}" ]]; then
  echo "ERROR: provekit-cli binary not found at ${PROVEKIT_BIN}" >&2
  echo "Build it first: cargo build --release --bin provekit-cli" >&2
  exit 1
fi

if [[ ! -d "${BENCH_ROOT}" ]]; then
  echo "ERROR: csp-benchmarks not found at ${BENCH_ROOT}" >&2
  exit 1
fi

if ! command -v nargo >/dev/null 2>&1; then
  echo "ERROR: nargo is required but not in PATH" >&2
  exit 1
fi

if ! python3 -c "import tomllib" 2>/dev/null; then
  echo "ERROR: python3.11+ is required (tomllib not found)." >&2
  echo "Current: $(python3 --version 2>&1)" >&2
  exit 1
fi

# Need GNU time (the `-f '%e %M'` format flag is GNU-specific). On Linux
# `/usr/bin/time` is GNU; on macOS it's BSD which doesn't accept `-f`, and
# GNU time is provided by `brew install gnu-time` as `gtime`. We probe each
# candidate to confirm it actually accepts `-f` before picking it.
TIME_BIN=""
for candidate in gtime /usr/bin/time; do
  if cand_path="$(command -v "${candidate}" 2>/dev/null)" \
     && "${cand_path}" -f '%e' true >/dev/null 2>&1; then
    TIME_BIN="${cand_path}"
    break
  fi
done
if [[ -z "${TIME_BIN}" ]]; then
  echo "ERROR: GNU time not found. On macOS: brew install gnu-time" >&2
  exit 1
fi

mkdir -p "${BENCH_DIR}/per_circuit"
RESULTS_CSV="${BENCH_DIR}/results.csv"
echo "circuit,backend,num_constraints,num_witnesses,prover_time_ms,prover_peak_rss_kb,prover_heap_peak_bytes,verifier_time_ms,proof_size_bytes,pkp_size_bytes,runs" > "${RESULTS_CSV}"

shopt -s nullglob

# Discover circuits: any direct subdir of csp-benchmarks/ that has both a
# Nargo.toml and a Prover.toml at its root. This filters out keccak_lib/.
discover_circuits() {
  for dir in "${BENCH_ROOT}"/*/; do
    if [[ -f "${dir}Nargo.toml" && -f "${dir}Prover.toml" ]]; then
      basename "${dir%/}"
    fi
  done
}

mapfile -t circuits < <(discover_circuits | sort)
if [[ "${#circuits[@]}" -eq 0 ]]; then
  echo "ERROR: no circuits discovered under ${BENCH_ROOT}" >&2
  exit 1
fi

echo "Discovered ${#circuits[@]} circuits"

# Read [package].name from a Nargo.toml; fall back to directory basename.
read_package_name() {
  local dir="$1"
  python3 - "$dir" <<'PY'
import sys, tomllib, pathlib
nargo = pathlib.Path(sys.argv[1]) / "Nargo.toml"
try:
    data = tomllib.loads(nargo.read_text())
    print(data.get("package", {}).get("name", ""))
except Exception:
    pass
PY
}

circuits_attempted=0
rows_attempted=0
rows_succeeded=0
rows_failed=0

for circuit in "${circuits[@]}"; do
  if [[ -n "${TEST_FILTER}" && ! "${circuit}" =~ ${TEST_FILTER} ]]; then
    continue
  fi
  (( circuits_attempted += 1 ))
  if [[ "${MAX_TESTS}" -gt 0 && "${circuits_attempted}" -gt "${MAX_TESTS}" ]]; then
    break
  fi

  workdir="${BENCH_ROOT}/${circuit}"

  echo ""
  echo "==> [${circuits_attempted}/${#circuits[@]}] ${circuit}"

  pkg_name="$(read_package_name "${workdir}")"
  if [[ -z "${pkg_name}" ]]; then
    pkg_name="${circuit}"
  fi

  # 1) compile (once per circuit; shared across backends)
  compile_log_dir="${BENCH_DIR}/per_circuit/${circuit}"
  mkdir -p "${compile_log_dir}"
  if ! (cd "${workdir}" && nargo compile > "${compile_log_dir}/compile.log" 2>&1); then
    echo "FAIL: nargo compile (${circuit})"
    # Compile failure means every backend row for this circuit is impossible.
    for backend in ${BENCH_BACKENDS}; do
      (( rows_attempted += 1 ))
      (( rows_failed += 1 ))
    done
    continue
  fi

  circuit_json="${workdir}/target/${pkg_name}.json"
  if [[ ! -f "${circuit_json}" ]]; then
    # Fallback: pick the first json under target/.
    candidate=("${workdir}"/target/*.json)
    if [[ "${#candidate[@]}" -gt 0 ]]; then
      circuit_json="${candidate[0]}"
    else
      echo "FAIL: no compiled JSON in ${workdir}/target/"
      for backend in ${BENCH_BACKENDS}; do
        (( rows_attempted += 1 ))
        (( rows_failed += 1 ))
      done
      continue
    fi
  fi

  for backend in ${BENCH_BACKENDS}; do
    (( rows_attempted += 1 ))

    if [[ "${backend}" == "groth16" && -n "${BENCH_SKIP_GROTH16}" \
          && "${circuit}" =~ ${BENCH_SKIP_GROTH16} ]]; then
      echo "SKIP: ${circuit} on ${backend} (matched BENCH_SKIP_GROTH16)"
      continue
    fi

    out_dir="${BENCH_DIR}/per_circuit/${circuit}/${backend}"
    mkdir -p "${out_dir}"

    pkp_path="${out_dir}/prover.pkp"
    pkv_path="${out_dir}/verifier.pkv"
    proof_path="${out_dir}/proof.np"

    echo "  -- backend: ${backend}"

    # 2) prepare (with backend selection)
    if ! (cd "${workdir}" && "${PROVEKIT_BIN}" prepare "${circuit_json}" \
            --backend "${backend}" \
            --pkp "${pkp_path}" --pkv "${pkv_path}") > "${out_dir}/prepare.log" 2>&1; then
      echo "FAIL: provekit-cli prepare ${backend} (${circuit})"
      (( rows_failed += 1 ))
      continue
    fi

    pkp_size_bytes="$(stat -c '%s' "${pkp_path}" 2>/dev/null || stat -f '%z' "${pkp_path}")"

    # 3) prove × BENCH_RUNS — write each run's stderr separately so the helper
    #    can parse the tracing output's "peak memory" lines.
    prove_ok=1
    for ((i=1; i<=BENCH_RUNS; i++)); do
      if ! (cd "${workdir}" && "${TIME_BIN}" -f '%e %M' \
              -o "${out_dir}/prove_${i}.time" \
              "${PROVEKIT_BIN}" prove \
                --prover "${pkp_path}" \
                --input "${workdir}/Prover.toml" \
                -o "${proof_path}") 2> "${out_dir}/prove_${i}.stderr"; then
        echo "FAIL: provekit-cli prove ${backend} run ${i} (${circuit})"
        prove_ok=0
        break
      fi
    done
    if [[ "${prove_ok}" -ne 1 ]]; then
      (( rows_failed += 1 ))
      continue
    fi

    proof_size_bytes="$(stat -c '%s' "${proof_path}" 2>/dev/null || stat -f '%z' "${proof_path}")"

    # 4) verify × BENCH_RUNS
    verify_ok=1
    for ((i=1; i<=BENCH_RUNS; i++)); do
      if ! (cd "${workdir}" && "${TIME_BIN}" -f '%e %M' \
              -o "${out_dir}/verify_${i}.time" \
              "${PROVEKIT_BIN}" verify \
                --verifier "${pkv_path}" \
                --proof "${proof_path}") \
              2> "${out_dir}/verify_${i}.stderr"; then
        echo "FAIL: provekit-cli verify ${backend} run ${i} (${circuit})"
        verify_ok=0
        break
      fi
    done
    if [[ "${verify_ok}" -ne 1 ]]; then
      (( rows_failed += 1 ))
      continue
    fi

    cat > "${out_dir}/meta.txt" <<EOF
pkp_size_bytes=${pkp_size_bytes}
proof_size_bytes=${proof_size_bytes}
EOF

    row="$(python3 "${HELPER}" parse-runs "${BENCH_DIR}" "${circuit}" "${backend}")"
    if [[ -n "${row}" ]]; then
      echo "${row}" >> "${RESULTS_CSV}"
      echo "OK: ${row}"
      (( rows_succeeded += 1 ))
    else
      echo "FAIL: helper produced no row for ${circuit}/${backend}"
      (( rows_failed += 1 ))
    fi
  done
done

echo ""
echo "----- csp-benchmarks summary -----"
echo "Discovered      : ${#circuits[@]}"
echo "Circuits tried  : ${circuits_attempted}"
echo "Backends        : ${BENCH_BACKENDS}"
echo "Rows attempted  : ${rows_attempted}"
echo "Rows succeeded  : ${rows_succeeded}"
echo "Rows failed     : ${rows_failed}"
echo "Results         : ${RESULTS_CSV}"

if [[ "${rows_failed}" -gt 0 ]]; then
  exit 1
fi
exit 0
