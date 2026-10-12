#!/usr/bin/env bash
# Compare proofs, public inputs, prove time and proof size across Noir and Mavros.
# Usage: scripts/mavros_parity.sh [--cli PATH] [--mavros PATH] [--out DIR] CIRCUIT_DIR...
# Each binary package needs Prover.toml, including a declared return when present.
# Exit non-zero on frontend failure or differing public inputs.
set -euo pipefail

CLI="${PROVEKIT_CLI:-target/release/provekit-cli}"
MAVROS="${MAVROS_CLI:-mavros}"
OUT="${PARITY_OUT:-target/mavros-parity}"
CIRCUITS=()
usage() { echo "usage: $0 [--cli PATH] [--mavros PATH] [--out DIR] CIRCUIT_DIR..."; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cli) CLI="$2"; shift 2 ;;
    --mavros) MAVROS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) CIRCUITS+=("$1"); shift ;;
  esac
done
if [[ ${#CIRCUITS[@]} -eq 0 ]]; then
  usage >&2
  exit 2
fi
CLI=$(cd "$(dirname "$CLI")" && pwd)/$(basename "$CLI")
if [[ "$MAVROS" == */* ]]; then
  MAVROS=$(cd "$(dirname "$MAVROS")" && pwd)/$(basename "$MAVROS")
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "print(f'{$2 - $1:.2f}')"; }
file_size() { wc -c < "$1" | tr -d ' '; }

# run_frontend NAME CIRCUIT_DIR WORK_DIR -> writes NAME.pkp/.pkv/.np and NAME.inputs
# Prints "ok|fail prove_seconds proof_bytes".
run_frontend() {
  local name="$1" dir="$2" work="$3" log="$3/$1.log"
  local pkp="$work/$name.pkp" pkv="$work/$name.pkv" proof="$work/$name.np"
  : > "$log"
  if [[ "$name" == noir ]]; then
    "$CLI" prepare "$dir" --pkp "$pkp" --pkv "$pkv" >>"$log" 2>&1 || { echo "fail - -"; return; }
  else
    (cd "$dir" && "$MAVROS" compile) >>"$log" 2>&1 || { echo "fail - -"; return; }
    "$CLI" prepare --compiler mavros "$dir/target/basic.json" --r1cs "$dir/target/r1cs.bin" \
      --pkp "$pkp" --pkv "$pkv" >>"$log" 2>&1 || { echo "fail - -"; return; }
  fi
  local t0 t1
  t0=$(now)
  "$CLI" prove -p "$pkp" -i "$dir/Prover.toml" -o "$proof" >>"$log" 2>&1 || { echo "fail - -"; return; }
  t1=$(now)
  "$CLI" verify -v "$pkv" --proof "$proof" >>"$log" 2>&1 || { echo "fail - -"; return; }
  "$CLI" show-inputs "$pkv" "$proof" --hex > "$work/$name.inputs" 2>>"$log" || { echo "fail - -"; return; }
  echo "ok $(elapsed "$t0" "$t1") $(file_size "$proof")"
}

status=0
printf '%-24s %-6s %-9s %-9s %-7s %-9s %-9s %s\n' circuit noir "prove(s)" "proof(B)" mavros "prove(s)" "proof(B)" "public inputs"
for dir in "${CIRCUITS[@]}"; do
  dir=$(cd "$dir" && pwd)
  circuit=$(basename "$dir")
  work="$OUT/$circuit"
  mkdir -p "$work"
  read -r n_ok n_time n_size <<<"$(run_frontend noir "$dir" "$work")"
  read -r m_ok m_time m_size <<<"$(run_frontend mavros "$dir" "$work")"
  inputs="-"
  if [[ "$n_ok" == ok && "$m_ok" == ok ]]; then
    if diff -q "$work/noir.inputs" "$work/mavros.inputs" >/dev/null; then
      inputs="equal"
    else
      inputs="DIFFER"
      status=1
    fi
  else
    status=1
  fi
  printf '%-24s %-6s %-9s %-9s %-7s %-9s %-9s %s\n' \
    "$circuit" "$n_ok" "$n_time" "$n_size" "$m_ok" "$m_time" "$m_size" "$inputs"
done
echo
echo "Artifacts and logs: $OUT"
if [[ $status -ne 0 ]]; then
  echo "Mavros parity FAILED." >&2
fi
exit $status
