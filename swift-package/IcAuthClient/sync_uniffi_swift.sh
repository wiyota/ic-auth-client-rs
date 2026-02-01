#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="${ROOT_DIR}/swift-package/IcAuthClient"
GEN_DIR="${ROOT_DIR}/uniffi/generated/swift"
OUT_DIR="${PKG_DIR}/Sources/IcAuthClient"

if [[ ! -d "${GEN_DIR}" ]]; then
  echo "Generated Swift bindings not found at: ${GEN_DIR}"
  echo "Run ./uniffi/generate_swift.sh first."
  exit 1
fi

mkdir -p "${OUT_DIR}"

# Remove only previously generated files, keep hand-written Swift.
for file in "${GEN_DIR}"/*.swift; do
  base="$(basename "${file}")"
  if [[ -f "${OUT_DIR}/${base}" ]]; then
    rm -f "${OUT_DIR}/${base}"
  fi
done

cp -v "${GEN_DIR}"/*.swift "${OUT_DIR}/"

for file in "${OUT_DIR}"/*.swift; do
  perl -0pi -e 's/#if canImport\(ic_auth_clientFFI\)\nimport ic_auth_clientFFI\n#endif/#if canImport(IcAuthClientFFI)\nimport IcAuthClientFFI\n#elseif canImport(ic_auth_clientFFI)\nimport ic_auth_clientFFI\n#endif/g' "${file}"
done

echo "Synced UniFFI Swift sources into: ${OUT_DIR}"
