#!/usr/bin/env bash
# run_csp_benchmarks.sh
#
# Run prove/verify benchmarks for noir-examples/csp-benchmarks/*. Each circuit
# is compiled and prepared once, then prove + verify are each invoked
# BENCH_RUNS times so the helper can average wall time, peak RSS, and
# heap-peak bytes (parsed from the prover's tracing output).
#
# Environment variables (all optional):
#   PROVEKIT_BIN     Path to provekit-cli (default: target/release/provekit-cli)
#   BENCH_ROOT       Path to csp-benchmarks (default: noir-examples/csp-benchmarks)
#   BENCH_DIR        Output directory (default: csp-bench-logs)
#   BENCH_RUNS       Iterations to average (default: 3)
#   TEST_FILTER      Regex on circuit name
#   MAX_TESTS        Cap on circuits (0 = unlimited)
#
# Output: BENCH_DIR/results.csv with one row per circuit:
#   circuit,num_constraints,num_witnesses,prover_time_ms,prover_peak_rss_kb,
#     prover_heap_peak_bytes,verifier_time_ms,proof_size_bytes,pkp_size_bytes,
#     runs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELPER="${SCRIPT_DIR}/csp_benchmark_helpers.py"

PROVEKIT_BIN="${PROVEKIT_BIN:-${REPO_ROOT}/target/release/provekit-cli}"
BENCH_ROOT="${BENCH_ROOT:-${REPO_ROOT}/noir-examples/csp-benchmarks}"
BENCH_DIR="${BENCH_DIR:-${REPO_ROOT}/csp-bench-logs}"
BENCH_RUNS="${BENCH_RUNS:-3}"
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

# `/usr/bin/time` is the GNU-style binary; macOS ships a different `time` shell
# builtin so users may need `gtime` from `brew install gnu-time`. CI runs on
# ubuntu-24.04-arm where /usr/bin/time is GNU.
TIME_BIN=""
if [[ -x /usr/bin/time ]]; then
  TIME_BIN=/usr/bin/time
elif command -v gtime >/dev/null 2>&1; then
  TIME_BIN="$(command -v gtime)"
else
  echo "ERROR: GNU /usr/bin/time not found (try: brew install gnu-time)" >&2
  exit 1
fi

mkdir -p "${BENCH_DIR}/per_circuit"
RESULTS_CSV="${BENCH_DIR}/results.csv"
echo "circuit,num_constraints,num_witnesses,prover_time_ms,prover_peak_rss_kb,prover_heap_peak_bytes,verifier_time_ms,proof_size_bytes,pkp_size_bytes,runs" > "${RESULTS_CSV}"

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

attempted=0
succeeded=0
failed=0

for circuit in "${circuits[@]}"; do
  if [[ -n "${TEST_FILTER}" && ! "${circuit}" =~ ${TEST_FILTER} ]]; then
    continue
  fi
  (( attempted += 1 ))
  if [[ "${MAX_TESTS}" -gt 0 && "${attempted}" -gt "${MAX_TESTS}" ]]; then
    break
  fi

  workdir="${BENCH_ROOT}/${circuit}"
  out_dir="${BENCH_DIR}/per_circuit/${circuit}"
  mkdir -p "${out_dir}"

  echo ""
  echo "==> [${attempted}/${#circuits[@]}] ${circuit}"

  pkg_name="$(read_package_name "${workdir}")"
  if [[ -z "${pkg_name}" ]]; then
    pkg_name="${circuit}"
  fi

  # 1) compile
  if ! (cd "${workdir}" && nargo compile > "${out_dir}/compile.log" 2>&1); then
    echo "FAIL: nargo compile (${circuit})"
    (( failed += 1 ))
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
      (( failed += 1 ))
      continue
    fi
  fi

  pkp_path="${out_dir}/prover.pkp"
  pkv_path="${out_dir}/verifier.pkv"
  proof_path="${out_dir}/proof.np"

  # 2) prepare
  if ! (cd "${workdir}" && "${PROVEKIT_BIN}" prepare "${circuit_json}" \
        --pkp "${pkp_path}" --pkv "${pkv_path}") > "${out_dir}/prepare.log" 2>&1; then
    echo "FAIL: provekit-cli prepare (${circuit})"
    (( failed += 1 ))
    continue
  fi

  pkp_size_bytes="$(stat -c '%s' "${pkp_path}" 2>/dev/null || stat -f '%z' "${pkp_path}")"

  # 3) prove × BENCH_RUNS — write each run's stderr separately so the helper
  #    can parse the tracing output's "peak memory" lines.
  prove_ok=1
  for ((i=1; i<=BENCH_RUNS; i++)); do
    if ! (cd "${workdir}" && "${TIME_BIN}" -f '%e %M' \
            -o "${out_dir}/prove_${i}.time" \
            "${PROVEKIT_BIN}" prove "${pkp_path}" "${workdir}/Prover.toml" \
            -o "${proof_path}") 2> "${out_dir}/prove_${i}.stderr"; then
      echo "FAIL: provekit-cli prove run ${i} (${circuit})"
      prove_ok=0
      break
    fi
  done
  if [[ "${prove_ok}" -ne 1 ]]; then
    (( failed += 1 ))
    continue
  fi

  proof_size_bytes="$(stat -c '%s' "${proof_path}" 2>/dev/null || stat -f '%z' "${proof_path}")"

  # 4) verify × BENCH_RUNS
  verify_ok=1
  for ((i=1; i<=BENCH_RUNS; i++)); do
    if ! (cd "${workdir}" && "${TIME_BIN}" -f '%e %M' \
            -o "${out_dir}/verify_${i}.time" \
            "${PROVEKIT_BIN}" verify "${pkv_path}" "${proof_path}") \
            2> "${out_dir}/verify_${i}.stderr"; then
      echo "FAIL: provekit-cli verify run ${i} (${circuit})"
      verify_ok=0
      break
    fi
  done
  if [[ "${verify_ok}" -ne 1 ]]; then
    (( failed += 1 ))
    continue
  fi

  cat > "${out_dir}/meta.txt" <<EOF
pkp_size_bytes=${pkp_size_bytes}
proof_size_bytes=${proof_size_bytes}
EOF

  row="$(python3 "${HELPER}" parse-runs "${BENCH_DIR}" "${circuit}")"
  if [[ -n "${row}" ]]; then
    echo "${row}" >> "${RESULTS_CSV}"
    echo "OK: ${row}"
    (( succeeded += 1 ))
  else
    echo "FAIL: helper produced no row for ${circuit}"
    (( failed += 1 ))
  fi
done

echo ""
echo "----- csp-benchmarks summary -----"
echo "Discovered : ${#circuits[@]}"
echo "Attempted  : ${attempted}"
echo "Succeeded  : ${succeeded}"
echo "Failed     : ${failed}"
echo "Results    : ${RESULTS_CSV}"

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi
exit 0
