#!/usr/bin/env bash
#
# Field-backend dependency-separation guard (fail-closed): the 64-bit Goldilocks
# backend must never pull a bn254/256-bit crate, and neither backend may depend on
# the other. A --all-features build cannot catch this; this can.
set -euo pipefail

# Workspace-local crates the Goldilocks graph may contain (field-agnostic spine +
# the backend itself). Every bn254-specific workspace crate is a local path dep,
# so any one leaking in trips this allowlist with zero list maintenance.
ALLOWED_LOCAL='provekit-backend-goldilocks provekit-common provekit-prover provekit-verifier'

# External bn254/256-bit families the allowlist can't see (crates.io / git deps):
# curve stacks and the Noir/Mavros frontend. Defense-in-depth; extend as needed.
FORBIDDEN_EXTERNAL='^(ark-bn254|ark-ec|ark-poly|ark-grumpkin|grumpkin|k256|p256|ecdsa|elliptic-curve|crypto-bigint|primefield|primeorder|sec1|rfc6979|acir|acir_field|acvm|acvm_blackbox_solver|brillig|brillig_vm|nargo|noirc_abi|noirc_printable_type|noirc_span|mavros-vm|mavros-artifacts|mavros-opcode-gen) '

backend_tree() {
  # Fail closed: a cargo-tree error or empty graph means we never inspected it.
  local pkg="$1" out
  if ! out=$(cargo tree -p "$pkg" -e normal --prefix none); then
    echo "ERROR: 'cargo tree -p $pkg' failed; cannot verify field separation." >&2
    exit 1
  fi
  if [[ -z "$out" ]]; then
    echo "ERROR: 'cargo tree -p $pkg' returned an empty graph." >&2
    exit 1
  fi
  printf '%s\n' "$out"
}

gold=$(backend_tree provekit-backend-goldilocks)
bn254=$(backend_tree provekit-backend-bn254)

fail=0

# (1) Allowlist: local path deps render as "name vX.Y.Z (/abs/path)".
while read -r name; do
  [[ -z "$name" ]] && continue
  if [[ " $ALLOWED_LOCAL " != *" $name "* ]]; then
    echo "ERROR: goldilocks backend pulls a non-spine workspace crate: $name" >&2
    fail=1
  fi
done < <(grep -E ' \(/' <<<"$gold" | awk '{print $1}' | sort -u)

# (2) Denylist: external bn254/256-bit families.
leak=$(sort -u <<<"$gold" | grep -E "$FORBIDDEN_EXTERNAL" || true)
if [[ -n "$leak" ]]; then
  echo "ERROR: goldilocks backend leaked bn254/256-bit external crates:" >&2
  printf '%s\n' "$leak" >&2
  fail=1
fi

# (3) Cross-backend: neither may depend on the other.
if grep -qE '^provekit-backend-bn254 ' <<<"$gold"; then
  echo 'ERROR: goldilocks backend depends on the bn254 backend.' >&2
  fail=1
fi
if grep -qE '^provekit-backend-goldilocks ' <<<"$bn254"; then
  echo 'ERROR: bn254 backend depends on the goldilocks backend.' >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo 'OK: field-backend dependency separation holds.'
