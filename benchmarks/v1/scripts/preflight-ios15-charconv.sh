#!/usr/bin/env bash

set -euo pipefail

ipa="${1:?usage: preflight-ios15-charconv.sh <app.ipa>}"
for command in find nm unzip; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "error: ${command} is required" >&2
    exit 1
  }
done
[[ -f "${ipa}" ]] || {
  echo "error: IPA not found: ${ipa}" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/provekit-charconv-preflight.XXXXXX")"
cleanup() {
  case "${work}" in
    "${TMPDIR:-/tmp}"/provekit-charconv-preflight.*) rm -rf "${work}" ;;
    *) echo "error: refusing to clean unexpected preflight path: ${work}" >&2 ;;
  esac
}
trap cleanup EXIT

unzip -q "${ipa}" -d "${work}"
app="$(find "${work}/Payload" -maxdepth 1 -type d -name '*.app' -print -quit)"
[[ -n "${app}" ]] || {
  echo "error: packaged app not found in ${ipa}" >&2
  exit 1
}
executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${app}/Info.plist")"
binary="${app}/${executable}"
[[ -f "${binary}" ]] || {
  echo "error: packaged executable not found: ${binary}" >&2
  exit 1
}

if nm -u "${binary}" |
  grep -Eq '__ZNSt3__18to_charsEPcS0_[fde]($|NS_12chars_formatE(i)?$)'; then
  echo "error: ${ipa} still imports iOS 15-incompatible floating to_chars" >&2
  exit 1
fi

echo "Validated iOS 15 charconv compatibility in ${ipa}"
