#!/usr/bin/env bash

set -euo pipefail

readonly java_version="temurin-21.0.11+10.0.LTS"
command -v mise >/dev/null 2>&1 || {
  echo "error: mise is required to install the locked Android JDK" >&2
  exit 1
}
mise install "java@${java_version}"
java_home="$(mise where "java@${java_version}")"
"${java_home}/bin/java" -version
