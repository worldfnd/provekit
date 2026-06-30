#!/usr/bin/env bash
#
# Field-backend dependency-separation guard.
#
# Enforces the invariant that the 64-bit Goldilocks backend and the 256-bit
# bn254 backend never share a field-specific dependency graph: the Goldilocks
# backend must NOT pull any bn254/256-bit crate, and neither backend may depend
# on the other.
#
# Design (fail-closed):
#   1. Capture each backend's runtime dep graph; abort if `cargo tree` errors or
#      returns nothing — a guard that cannot inspect the graph must NOT pass.
#   2. ALLOWLIST the local (workspace path) crates the Goldilocks graph may
#      contain. This is the robust core: every bn254-specific workspace crate
#      (backend-bn254, skyscraper, ntt, poseidon2, bn254-multiplier{,-codegen},
#      fp-rounding, hla) is a local path dependency, so any one leaking in is
#      caught automatically with zero list maintenance.
#   3. DENYLIST the bn254/256-bit *external* crate families (crates.io / git
#      deps the allowlist can't see): the curve stacks and the Noir/Mavros
#      frontend. This is defense-in-depth; extend it if a new curve dep appears.
set -euo pipefail

# --- Local (workspace) crates the Goldilocks graph is permitted to contain.
# Only the field-agnostic spine + the goldilocks backend itself. Anything else
# with a workspace path (a sibling crate) is a leak.
ALLOWED_LOCAL='provekit-backend-goldilocks provekit-common provekit-prover provekit-verifier'

# --- External bn254/256-bit crate families that must never reach Goldilocks.
# Anchored at column 0 with a trailing space to match "name vX.Y.Z" lines.
FORBIDDEN_EXTERNAL='^(ark-bn254|ark-ec|ark-poly|ark-grumpkin|grumpkin|k256|p256|ecdsa|elliptic-curve|crypto-bigint|primefield|primeorder|sec1|rfc6979|acir|acir_field|acvm|acvm_blackbox_solver|brillig|brillig_vm|nargo|noirc_abi|noirc_printable_type|noirc_span|mavros-vm|mavros-artifacts|mavros-opcode-gen) '

backend_tree() {
  # Fail closed: surface cargo tree errors instead of swallowing them, and
  # treat an empty graph as a failure (it means we never actually inspected it).
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

# (1) Allowlist check on local workspace crates in the goldilocks graph.
# Local path deps render as "name vX.Y.Z (/abs/path/...)"; extract their names.
while read -r name; do
  [[ -z "$name" ]] && continue
  if ! grep -qw -- "$name" <<<"$ALLOWED_LOCAL"; then
    echo "ERROR: goldilocks backend pulls a non-spine workspace crate: $name" >&2
    fail=1
  fi
done < <(grep -E ' \(/' <<<"$gold" | awk '{print $1}' | sort -u)

# (2) Denylist check on external bn254/256-bit crate families.
leak=$(sort -u <<<"$gold" | grep -E "$FORBIDDEN_EXTERNAL" || true)
if [[ -n "$leak" ]]; then
  echo "ERROR: goldilocks backend leaked bn254/256-bit external crates:" >&2
  printf '%s\n' "$leak" >&2
  fail=1
fi

# (3) Explicit, anchored cross-backend checks.
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
