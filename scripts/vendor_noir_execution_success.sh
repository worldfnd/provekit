#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST_EXEC_DIR="${REPO_ROOT}/test-programs/noir/execution_success"
DEST_LIB_DIR="${REPO_ROOT}/test-programs/noir/test_libraries"
NOIR_REF="${NOIR_REF:-v1.0.0-beta.19}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

echo "Vendoring noir-lang/noir:test_programs/{execution_success,test_libraries} (ref: ${NOIR_REF})"

git clone --depth 1 --filter=blob:none --sparse --branch "${NOIR_REF}" \
  "https://github.com/noir-lang/noir.git" "${tmpdir}/noir"
git -C "${tmpdir}/noir" sparse-checkout set \
  "test_programs/execution_success" \
  "test_programs/test_libraries"

mkdir -p "$(dirname "${DEST_EXEC_DIR}")"
rm -rf "${DEST_EXEC_DIR}" "${DEST_LIB_DIR}"
cp -R "${tmpdir}/noir/test_programs/execution_success" "${DEST_EXEC_DIR}"
cp -R "${tmpdir}/noir/test_programs/test_libraries" "${DEST_LIB_DIR}"

source_commit="$(git -C "${tmpdir}/noir" rev-parse HEAD)"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "${REPO_ROOT}/test-programs/noir/execution_success.SOURCE" <<EOF
repository=https://github.com/noir-lang/noir
ref=${NOIR_REF}
commit=${source_commit}
generated_at_utc=${generated_at}
source_paths=test_programs/execution_success,test_programs/test_libraries
EOF

echo "Done. Vendored files updated at ${DEST_EXEC_DIR} and ${DEST_LIB_DIR}"
echo "Source metadata written to test-programs/noir/execution_success.SOURCE"
