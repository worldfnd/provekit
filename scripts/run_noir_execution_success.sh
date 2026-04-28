#!/usr/bin/env bash
# run_noir_execution_success.sh
#
# Run the Noir execution_success test suite through provekit-cli.
#
# Environment variables (all optional):
#   NOIR_REPO_DIR            Path to a cloned noir-lang/noir repo root.
#                            When set, tests come from
#                            NOIR_REPO_DIR/test_programs/{execution_success,test_libraries}.
#                            When unset, falls back to the vendored path
#                            REPO_ROOT/test-programs/noir/.
#   PROVEKIT_BIN             Path to provekit-cli binary (default: target/release/provekit-cli)
#   LOG_DIR                  Directory for per-test logs and summary
#   MAX_TESTS                Cap the number of tests (0 = unlimited)
#   TEST_FILTER              Regex filter on test name
#   REQUIRED_NARGO_VERSION   Nargo version string to require (default 1.0.0-beta.19)
#   ENABLE_ENUMS_FALLBACK    Retry compile with -Zenums on 'enums' feature error (0/1, default 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELPER="${SCRIPT_DIR}/noir_execution_helpers.py"
SKIP_LIST_FILE="${SCRIPT_DIR}/noir_skip_tests.txt"

# ---------------------------------------------------------------------------
# Resolve test corpus root (CI clone vs. local vendored copy)
# ---------------------------------------------------------------------------
if [[ -n "${NOIR_REPO_DIR:-}" ]]; then
  TEST_ROOT="${NOIR_REPO_DIR}/test_programs/execution_success"
  TEST_LIB_ROOT="${NOIR_REPO_DIR}/test_programs/test_libraries"
else
  NOIR_ROOT="${REPO_ROOT}/test-programs/noir"
  TEST_ROOT="${NOIR_ROOT}/execution_success"
  TEST_LIB_ROOT="${NOIR_ROOT}/test_libraries"
fi

PROVEKIT_BIN="${PROVEKIT_BIN:-${REPO_ROOT}/target/release/provekit-cli}"
MAX_TESTS="${MAX_TESTS:-0}"
REQUIRED_NARGO_VERSION="${REQUIRED_NARGO_VERSION:-1.0.0-beta.19}"
ENABLE_ENUMS_FALLBACK="${ENABLE_ENUMS_FALLBACK:-1}"
TEST_FILTER="${TEST_FILTER:-}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${LOG_DIR:-${REPO_ROOT}/scripts/noir_execution_logs/${RUN_ID}}"

if [[ "${LOG_DIR}" != /* ]]; then
  LOG_DIR="${REPO_ROOT}/${LOG_DIR}"
fi

# ---------------------------------------------------------------------------
# Unimplemented-blackbox skip list
# Single source of truth: scripts/noir_skip_tests.txt (shared with
# scripts/generate_provekit_witness_report.py). Counted as SKIP (not FAIL).
# ---------------------------------------------------------------------------
SKIP_TESTS=()
declare -A SKIP_SET
if [[ -f "${SKIP_LIST_FILE}" ]]; then
  while IFS= read -r _raw || [[ -n "${_raw}" ]]; do
    _name="${_raw%%#*}"
    _name="${_name#"${_name%%[![:space:]]*}"}"
    _name="${_name%"${_name##*[![:space:]]}"}"
    if [[ -n "${_name}" ]]; then
      SKIP_TESTS+=("${_name}")
      SKIP_SET["${_name}"]=1
    fi
  done < "${SKIP_LIST_FILE}"
else
  echo "WARNING: skip list ${SKIP_LIST_FILE} not found; no tests will be skipped." >&2
fi

if [[ ! -d "${TEST_ROOT}" ]]; then
  echo "ERROR: Missing test corpus at ${TEST_ROOT}"
  if [[ -z "${NOIR_REPO_DIR:-}" ]]; then
    echo "Hint: run scripts/vendor_noir_execution_success.sh first, or set NOIR_REPO_DIR."
  else
    echo "Hint: check that NOIR_REPO_DIR (${NOIR_REPO_DIR}) contains test_programs/execution_success."
  fi
  exit 1
fi

if [[ ! -x "${PROVEKIT_BIN}" ]]; then
  echo "Missing provekit-cli binary at ${PROVEKIT_BIN}"
  echo "Build it first: cargo build --release --bin provekit-cli"
  exit 1
fi

if ! command -v nargo >/dev/null 2>&1; then
  echo "nargo is required but was not found in PATH."
  echo "Install with noirup and set version: noirup --version v1.0.0-beta.19"
  exit 1
fi

nargo_version="$(nargo --version)"
if [[ "${nargo_version}" != *"${REQUIRED_NARGO_VERSION}"* ]]; then
  echo "Unsupported nargo version: ${nargo_version}"
  echo "Expected version containing: ${REQUIRED_NARGO_VERSION}"
  echo "Switch with: noirup --version ${REQUIRED_NARGO_VERSION}"
  exit 1
fi

if ! python3 -c "import tomllib" 2>/dev/null; then
  echo "ERROR: python3.11+ is required (tomllib not found)."
  echo "Current: $(python3 --version 2>&1)"
  exit 1
fi

mkdir -p "${LOG_DIR}/per_test"
GROUPED_REPORT_FILE="${LOG_DIR}/grouped_error_report.txt"
WITNESS_CSV="${LOG_DIR}/provekit_witness_counts.csv"
echo "test_name,provekit_constraints,provekit_witnesses" > "${WITNESS_CSV}"

shopt -s nullglob globstar

# Python helpers live in scripts/noir_execution_helpers.py; these are thin
# shell wrappers so the main loop reads naturally.
discover_test_dirs() {
  python3 "${HELPER}" discover "${TEST_ROOT}"
}

resolve_prover_toml() {
  python3 "${HELPER}" resolve-prover-toml "$1" "$2"
}

read_workdir_package_name() {
  python3 "${HELPER}" package-name "$1"
}

relative_path() {
  python3 -c 'import os, sys; print(os.path.relpath(sys.argv[2], sys.argv[1]))' "$1" "$2"
}



append_stage_marker() {
  local log_file="$1"
  local stage_name="$2"
  local stage_status="$3"
  printf '\n[%s] %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${stage_status}" "${stage_name}" >> "${log_file}"
}

mapfile -t test_dirs < <(discover_test_dirs)

if [[ "${#test_dirs[@]}" -eq 0 ]]; then
  echo "No runnable test programs found under ${TEST_ROOT}"
  exit 1
fi

total=0
passed=0
failed=0
skipped=0

# Clean up the active test sandbox if the script exits unexpectedly (SIGINT, error).
_current_sandbox=""
_cleanup_sandbox() {
  if [[ -n "${_current_sandbox:-}" && -d "${_current_sandbox}" ]]; then
    rm -rf "${_current_sandbox}"
  fi
}
trap _cleanup_sandbox EXIT INT TERM

if [[ ! -d "${TEST_LIB_ROOT}" ]]; then
  echo "WARNING: missing ${TEST_LIB_ROOT}; path-based dependency tests may fail."
  echo "Run scripts/vendor_noir_execution_success.sh to vendor test_libraries as well."
fi

for test_name in "${test_dirs[@]}"; do
  if [[ -n "${TEST_FILTER}" && ! "${test_name}" =~ ${TEST_FILTER} ]]; then
    continue
  fi

  # leaf name (no sub-path) is what we key on in the skip set
  leaf_name="${test_name%%/*}"

  # --- Unimplemented blackbox skip list: no log, no noise ---
  # Skip BEFORE incrementing `total` so MAX_TESTS caps only attempted tests.
  if [[ "${SKIP_SET["${leaf_name}"]:-}" == "1" ]]; then
    echo "SKIP (blackbox): ${test_name}"
    (( skipped += 1 ))
    continue
  fi

  (( total += 1 ))

  if [[ "${MAX_TESTS}" -gt 0 && "${total}" -gt "${MAX_TESTS}" ]]; then
    break
  fi

  test_dir="${TEST_ROOT}/${test_name}"
  safe_test_name="${test_name//\//__}"

  test_log="${LOG_DIR}/per_test/${safe_test_name}.log"

  echo ""
  echo "==> [${total}] ${test_name}"

  : > "${test_log}"
  {
    echo "test_name=${test_name}"
    echo "test_dir=${test_dir}"
    echo "run_id=${RUN_ID}"
    echo "nargo_version=${nargo_version}"
  } >> "${test_log}"

  if [[ ! -f "${test_dir}/Nargo.toml" ]]; then
    echo "SKIP: missing Nargo.toml"
    append_stage_marker "${test_log}" "test" "SKIP"
    echo "SKIP: missing Nargo.toml" >> "${test_log}"
    (( skipped += 1 ))
    continue
  fi

  if [[ ! -d "${TEST_LIB_ROOT}" ]] && grep -q 'test_libraries' "${test_dir}"/Nargo.toml 2>/dev/null; then
    echo "SKIP: missing test_libraries for relative path dependency"
    append_stage_marker "${test_log}" "test" "SKIP"
    echo "SKIP: missing test_libraries for relative path dependency" >> "${test_log}"
    (( skipped += 1 ))
    continue
  fi

  sandbox_root="$(mktemp -d)"
  _current_sandbox="${sandbox_root}"
  sandbox_noir_root="${sandbox_root}/test-programs/noir"
  sandbox_exec_root="${sandbox_noir_root}/execution_success"
  fixture_name="${test_name%%/*}"
  fixture_src="${TEST_ROOT}/${fixture_name}"
  fixture_dst="${sandbox_exec_root}/${fixture_name}"

  mkdir -p "${sandbox_exec_root}"
  cp -R "${fixture_src}" "${fixture_dst}"

  if [[ -d "${TEST_LIB_ROOT}" ]]; then
    mkdir -p "${sandbox_noir_root}"
    ln -s "${TEST_LIB_ROOT}" "${sandbox_noir_root}/test_libraries"
  fi

  workdir="${sandbox_exec_root}/${test_name}"
  echo "sandbox_root=${sandbox_root}" >> "${test_log}"
  echo "workdir=${workdir}" >> "${test_log}"

  append_stage_marker "${test_log}" "nargo compile" "START"
  compile_ok=0

  if (cd "${workdir}" && nargo compile >> "${test_log}" 2>&1); then
    compile_ok=1
  elif [[ "${ENABLE_ENUMS_FALLBACK}" -eq 1 ]] && grep -q "unstable feature 'enums'" "${test_log}"; then
    append_stage_marker "${test_log}" "nargo compile -Zenums" "RETRY"
    if (cd "${workdir}" && nargo compile -Zenums >> "${test_log}" 2>&1); then
      compile_ok=1
    fi
  fi

  if [[ "${compile_ok}" -ne 1 ]]; then
    append_stage_marker "${test_log}" "nargo compile" "FAIL"
    echo "FAIL: nargo compile"
    echo "FAIL: nargo compile" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi

  append_stage_marker "${test_log}" "nargo compile" "PASS"

  compiled_jsons=("${workdir}"/target/*.json)
  if [[ "${#compiled_jsons[@]}" -eq 0 ]]; then
    compiled_jsons=("${sandbox_exec_root}/${fixture_name}"/target/*.json)
  fi
  if [[ "${#compiled_jsons[@]}" -eq 0 ]]; then
    compiled_jsons=("${sandbox_exec_root}/${fixture_name}"/**/target/*.json)
  fi
  if [[ "${#compiled_jsons[@]}" -eq 0 ]]; then
    append_stage_marker "${test_log}" "compile output check" "FAIL"
    echo "FAIL: missing compiled target JSON after nargo compile"
    echo "FAIL: missing compiled target JSON after nargo compile" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi

  workdir_package_name="$(read_workdir_package_name "${workdir}")"
  circuit_json_abs=""
  if [[ -n "${workdir_package_name}" ]]; then
    for candidate_json in "${compiled_jsons[@]}"; do
      if [[ "$(basename "${candidate_json}" .json)" == "${workdir_package_name}" ]]; then
        circuit_json_abs="${candidate_json}"
        break
      fi
    done
  fi
  if [[ -z "${circuit_json_abs}" ]]; then
    circuit_json_abs="${compiled_jsons[0]}"
  fi

  circuit_json="$(relative_path "${workdir}" "${circuit_json_abs}")"
  package_name="$(basename "${circuit_json_abs}" .json)"
  prover_toml_rel="$(resolve_prover_toml "${workdir}" "${package_name}")"

  if [[ -z "${prover_toml_rel}" || ! -f "${workdir}/${prover_toml_rel}" ]]; then
    append_stage_marker "${test_log}" "resolve prover.toml" "FAIL"
    echo "FAIL: could not locate Prover.toml for compiled package ${package_name}"
    echo "FAIL: could not locate Prover.toml for compiled package ${package_name}" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi

  echo "circuit_json=${circuit_json}" >> "${test_log}"
  echo "prover_toml=${prover_toml_rel}" >> "${test_log}"

  append_stage_marker "${test_log}" "provekit-cli prepare" "START"
  if ! (cd "${workdir}" && "${PROVEKIT_BIN}" prepare "./${circuit_json}" --pkp "./prover.pkp" --pkv "./verifier.pkv" >> "${test_log}" 2>&1); then
    append_stage_marker "${test_log}" "provekit-cli prepare" "FAIL"
    echo "FAIL: provekit-cli prepare"
    echo "FAIL: provekit-cli prepare" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi
  append_stage_marker "${test_log}" "provekit-cli prepare" "PASS"

  # Extract ProveKit post-GE constraint and witness counts before the log is deleted on success.
  # Keep this non-fatal under `set -euo pipefail` if the log format changes/misses.
  _ge_line="$(grep -o 'After GE optimization: [0-9]* constraints, [0-9]* witnesses' "${test_log}" | tail -1 || true)"
  _pk_constraints=""
  _pk_witnesses=""
  if [[ "${_ge_line}" =~ ([0-9]+)\ constraints,\ ([0-9]+)\ witnesses$ ]]; then
    _pk_constraints="${BASH_REMATCH[1]}"
    _pk_witnesses="${BASH_REMATCH[2]}"
  fi
  if [[ -n "${_pk_witnesses}" ]]; then
    echo "${test_name},${_pk_constraints},${_pk_witnesses}" >> "${WITNESS_CSV}"
  fi

  append_stage_marker "${test_log}" "provekit-cli prove" "START"
  if ! (cd "${workdir}" && "${PROVEKIT_BIN}" prove "./prover.pkp" "./${prover_toml_rel}" -o "./proof.np" >> "${test_log}" 2>&1); then
    append_stage_marker "${test_log}" "provekit-cli prove" "FAIL"
    echo "FAIL: provekit-cli prove"
    echo "FAIL: provekit-cli prove" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi
  append_stage_marker "${test_log}" "provekit-cli prove" "PASS"

  append_stage_marker "${test_log}" "provekit-cli verify" "START"
  if ! (cd "${workdir}" && "${PROVEKIT_BIN}" verify "./verifier.pkv" "./proof.np" >> "${test_log}" 2>&1); then
    append_stage_marker "${test_log}" "provekit-cli verify" "FAIL"
    echo "FAIL: provekit-cli verify"
    echo "FAIL: provekit-cli verify" >> "${test_log}"
    (( failed += 1 ))
    rm -rf "${sandbox_root}"
    continue
  fi
  append_stage_marker "${test_log}" "provekit-cli verify" "PASS"

  echo "PASS"
  (( passed += 1 ))
  rm -rf "${sandbox_root}"
  # Remove per-test log for passing tests to keep artifacts lean
  rm -f "${test_log}"
done

# Blackbox skips bump `skipped` without bumping `total` (see the skip block
# above), so summing passed+failed+skipped would double-count them.
attempted=${total}

echo ""
echo "----- execution_success summary -----"
echo "Total discovered : ${#test_dirs[@]}"
if [[ -n "${TEST_FILTER}" ]]; then
  echo "Test filter      : ${TEST_FILTER}"
fi
if [[ "${MAX_TESTS}" -gt 0 ]]; then
  echo "Attempted limit  : ${MAX_TESTS}"
else
  echo "Attempted limit  : all"
fi
echo "Attempted        : ${attempted}"
echo "Passed           : ${passed}"
echo "Failed           : ${failed}"
echo "Skipped          : ${skipped}  (${#SKIP_TESTS[@]} unimplemented-blackbox tests)"
echo "Log directory    : ${LOG_DIR}"

python3 "${HELPER}" build-report "${LOG_DIR}" "${passed}" "${failed}" "${skipped}"

# Emit GitHub Step Summary when running inside Actions
# (must be after the Python report generator so grouped_error_report.txt exists)
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Noir execution_success — ${RUN_ID}"
    echo ""
    echo "| Metric | Count |"
    echo "|--------|------|"
    echo "| Discovered | ${#test_dirs[@]} |"
    echo "| Attempted  | ${attempted} |"
    echo "| ✅ Passed  | ${passed} |"
    echo "| ❌ Failed  | ${failed} |"
    echo "| ⏭️ Skipped  | ${skipped} (${#SKIP_TESTS[@]} unimplemented blackboxes) |"
    if [[ ${failed} -gt 0 ]]; then
      echo ""
      echo "### Failure groups"
      echo '```'
      cat "${GROUPED_REPORT_FILE}" 2>/dev/null || echo "(no grouped report)"
      echo '```'
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi

echo "Grouped report  : ${GROUPED_REPORT_FILE}"

# Generate ProveKit witness count report
if [[ -f "${WITNESS_CSV}" ]] && python3 "${SCRIPT_DIR}/generate_provekit_witness_report.py" "${WITNESS_CSV}" "${LOG_DIR}"; then
  echo "ProveKit witness report: ${LOG_DIR}/provekit_witness_report.md"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo ""
      echo "## ProveKit Witness Counts"
      head -4 "${LOG_DIR}/provekit_witness_report.md"
      echo ""
      echo "_Full table available in artifact: \`provekit_witness_report.md\`_"
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
fi

# Circuit failures are surfaced via the PR sticky comment and the grouped
# error report. The workflow should not fail just because some circuits
# don't compile through provekit-cli today — the report is the source of
# truth for which circuits pass. Set STRICT_FAIL=1 to opt into the old
# "exit 1 on any failure" behaviour for local CI gates.
if [[ "${STRICT_FAIL:-0}" == "1" && "${failed}" -gt 0 ]]; then
  exit 1
fi

exit 0
