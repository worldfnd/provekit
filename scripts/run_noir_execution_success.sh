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
# These tests use blackbox functions not yet supported by provekit.
# They are counted as SKIP (not FAIL) and will be added back once supported.
# ---------------------------------------------------------------------------
SKIP_TESTS=(
  # BLAKE3
  a_6
  array_dynamic_blackbox_input
  array_dynamic_nested_blackbox_input
  blake3
  conditional_1
  conditional_regression_short_circuit
  regression_4449
  # ECDSA_SECP256K1
  bench_ecdsa_secp256k1
  ecdsa_secp256k1
  ecdsa_secp256k1_invalid_inputs
  ecdsa_secp256k1_invalid_pub_key_in_inactive_branch
  # ECDSA_SECP256R1
  ecdsa_secp256r1
  ecdsa_secp256r1_3x
  ecdsa_secp256r1_invalid_pub_key_in_inactive_branch
  ecdsa_secp256r1_msg_equals_order
  # EMBEDDED_CURVE_ADD
  embedded_curve_ops
  regression_5045
  regression_7744
  # AES128_ENCRYPT
  aes128_encrypt
  # BLAKE2S
  a_7
)

# Build a fast associative-array lookup
declare -A SKIP_SET
for _t in "${SKIP_TESTS[@]}"; do
  SKIP_SET["${_t}"]=1
done

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
echo "test_name,provekit_witnesses" > "${WITNESS_CSV}"

shopt -s nullglob globstar

discover_test_dirs() {
  TEST_ROOT="${TEST_ROOT}" python3 - <<'PY'
from pathlib import Path
import tomllib
import os

root = Path(os.environ["TEST_ROOT"])
nargo_data = {}

for nargo in root.rglob("Nargo.toml"):
    rel = nargo.parent.relative_to(root).as_posix()
    try:
        data = tomllib.loads(nargo.read_text())
    except Exception:
        data = {}
    nargo_data[rel] = data

workspace_default_roots = set()
for rel, data in nargo_data.items():
    ws = data.get("workspace")
    if isinstance(ws, dict) and "default-member" in ws:
        workspace_default_roots.add(rel)

suppressed = set()
for ws_rel in workspace_default_roots:
    ws_path = Path(ws_rel) if ws_rel != "." else Path()
    for rel in nargo_data:
        rel_path = Path(rel) if rel != "." else Path()
        if rel_path != ws_path and ws_path in rel_path.parents:
            suppressed.add(rel)

candidates = set(workspace_default_roots)
for rel, data in nargo_data.items():
    if rel in suppressed:
        continue

    pkg = data.get("package")
    if isinstance(pkg, dict) and "name" in pkg:
        if (root / rel / "Prover.toml").is_file():
            candidates.add(rel)

for rel in sorted(candidates):
    print(rel)
PY
}

resolve_prover_toml() {
  local project_dir="$1"
  local package_name="$2"

  PROJECT_DIR="${project_dir}" PACKAGE_NAME="${package_name}" python3 - <<'PY'
from pathlib import Path
import tomllib
import os

project_dir = Path(os.environ["PROJECT_DIR"])
package_name = os.environ["PACKAGE_NAME"]

candidates = []
for nargo in sorted(project_dir.rglob("Nargo.toml")):
    try:
        data = tomllib.loads(nargo.read_text())
    except Exception:
        continue

    pkg = data.get("package")
    if not isinstance(pkg, dict):
        continue

    if pkg.get("name") != package_name:
        continue

    prover = nargo.parent / "Prover.toml"
    if prover.is_file():
        candidates.append(prover.relative_to(project_dir).as_posix())

if candidates:
    candidates.sort(key=lambda p: (p.count("/"), p))
    print(candidates[0])
    raise SystemExit(0)

root_prover = project_dir / "Prover.toml"
if root_prover.is_file():
    print("Prover.toml")
    raise SystemExit(0)

all_provers = sorted(project_dir.rglob("Prover.toml"))
if len(all_provers) == 1:
    print(all_provers[0].relative_to(project_dir).as_posix())
    raise SystemExit(0)

print("")
PY
}

read_workdir_package_name() {
  local project_dir="$1"
  PROJECT_DIR="${project_dir}" python3 - <<'PY'
from pathlib import Path
import tomllib
import os

nargo = Path(os.environ["PROJECT_DIR"]) / "Nargo.toml"
if not nargo.is_file():
    print("")
    raise SystemExit(0)

try:
    data = tomllib.loads(nargo.read_text())
except Exception:
    print("")
    raise SystemExit(0)

pkg = data.get("package")
if isinstance(pkg, dict):
    print(pkg.get("name", ""))
else:
    print("")
PY
}

relative_path() {
  local from_dir="$1"
  local to_path="$2"
  FROM_DIR="${from_dir}" TO_PATH="${to_path}" python3 - <<'PY'
import os
print(os.path.relpath(os.environ["TO_PATH"], os.environ["FROM_DIR"]))
PY
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

  (( total += 1 ))

  if [[ "${MAX_TESTS}" -gt 0 && "${total}" -gt "${MAX_TESTS}" ]]; then
    break
  fi

  # leaf name (no sub-path) is what we key on in the skip set
  leaf_name="${test_name%%/*}"
  test_dir="${TEST_ROOT}/${test_name}"
  safe_test_name="${test_name//\//__}"
  # --- Unimplemented blackbox skip list: no log, no noise ---
  if [[ "${SKIP_SET["${leaf_name}"]:-}" == "1" ]]; then
    echo "SKIP (blackbox): ${test_name}"
    (( skipped += 1 ))
    continue
  fi

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

  if [[ ! -d "${TEST_LIB_ROOT}" ]] && grep -qr 'test_libraries' "${test_dir}"/Nargo.toml 2>/dev/null; then
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

  # Extract ProveKit post-GE witness count before the log is deleted on success
  _ge_line=$(grep -o 'After GE optimization: [0-9]* constraints, [0-9]* witnesses' "${test_log}" | tail -1)
  _pk_witnesses=$(echo "${_ge_line}" | grep -o '[0-9]* witnesses' | grep -o '^[0-9]*')
  if [[ -n "${_pk_witnesses}" ]]; then
    echo "${test_name},${_pk_witnesses}" >> "${WITNESS_CSV}"
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

attempted=$((passed + failed + skipped))

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

LOG_DIR="${LOG_DIR}" PASSED_COUNT="${passed}" python3 - <<'PY'
from pathlib import Path
import re
from collections import defaultdict
import os

log_dir = Path(os.environ["LOG_DIR"])
per_test_dir = log_dir / "per_test"
report_file = log_dir / "grouped_error_report.txt"

logs = sorted(per_test_dir.glob("*.log"))
# PASS logs are deleted after each successful test run; read the count from the shell instead.
status_counts = {"PASS": int(os.environ.get("PASSED_COUNT", "0")), "FAIL": 0, "SKIP": 0}
grouped = defaultdict(list)
stage_groups = defaultdict(list)

for fp in logs:
    text = fp.read_text(errors="replace")
    name = fp.stem

    if "SKIP:" in text:
        status_counts["SKIP"] += 1
        skip_reason = re.search(r"SKIP: ([^\n]+)", text)
        reason = skip_reason.group(1).strip() if skip_reason else "unknown"
        grouped[f"SKIP: {reason}"].append(name)
        continue

    status_counts["FAIL"] += 1
    fail_stage_match = re.findall(r"FAIL: ([^\n]+)", text)
    stage = fail_stage_match[-1].strip() if fail_stage_match else "unknown stage"
    stage_groups[stage].append(name)

    blackbox = re.search(r"not implemented: Other black box function: BLACKBOX::([A-Z0-9_]+)", text)
    if blackbox:
        grouped[f"Not implemented blackbox: {blackbox.group(1)} ({stage})"].append(name)
        continue

    if "Program must have one entry point." in text:
        grouped[f"Program must have one entry point ({stage})"].append(name)
        continue

    panic = re.search(r"panicked at [^\n]*:\n([^\n]+)", text)
    if panic:
        grouped[f"Panic: {panic.group(1).strip()} ({stage})"].append(name)
        continue

    solve = re.search(r"Failed to solve program: '([^']+)'", text)
    if solve:
        grouped[f"Failed to solve program: {solve.group(1)} ({stage})"].append(name)
        continue

    assertion = re.search(r"Failed assertion", text)
    if assertion:
        grouped[f"Failed assertion ({stage})"].append(name)
        continue

    compile_error = re.search(r"^error:\s*([^\n]+)", text, flags=re.M)
    if compile_error:
        grouped[f"Compile error: {compile_error.group(1).strip()} ({stage})"].append(name)
        continue

    compile_bug = re.search(r"^bug:\s*([^\n]+)", text, flags=re.M)
    if compile_bug:
        grouped[f"Compile bug: {compile_bug.group(1).strip()} ({stage})"].append(name)
        continue

    generic_error = re.search(r"^Error:\s*([^\n]+)", text, flags=re.M)
    if generic_error:
        grouped[f"Error: {generic_error.group(1).strip()} ({stage})"].append(name)
        continue

    grouped[f"Unknown failure ({stage})"].append(name)

with report_file.open("w") as f:
    f.write(f"logs={len(logs)}\n")
    f.write(f"PASS={status_counts['PASS']}\n")
    f.write(f"FAIL={status_counts['FAIL']}\n")
    f.write(f"SKIP={status_counts['SKIP']}\n")
    f.write("\n[stages]\n")
    for stage, tests in sorted(stage_groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        f.write(f"{stage}\t{len(tests)}\t{', '.join(tests)}")
        f.write("\n")
    f.write("\n[grouped]\n")
    for key, tests in sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        f.write(f"{len(tests)}\t{key}\t{', '.join(tests)}")
        f.write("\n")
PY

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

# Generate Mavros vs ProveKit witness comparison table
if [[ -f "${WITNESS_CSV}" ]] && python3 "${SCRIPT_DIR}/generate_witness_comparison.py" "${WITNESS_CSV}" "${LOG_DIR}"; then
  echo "Witness comparison: ${LOG_DIR}/witness_comparison.md"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo ""
      echo "## Mavros vs ProveKit Witness Count"
      head -4 "${LOG_DIR}/witness_comparison.md"
      echo ""
      echo "_Full table available in artifact: \`witness_comparison.md\`_"
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
fi

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi

exit 0
