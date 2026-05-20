#!/usr/bin/env bash
# check_version_drift.sh — assert Cargo.toml workspace version, CHANGELOG.md,
# and the git tag (when running on a tag build) all agree.
#
# Exit codes:
#   0 — versions agree
#   1 — drift detected (with a one-line diagnostic on stderr)
#   2 — environment issue (e.g. Cargo.toml unreadable)
#
# Wired into .github/workflows/ci.yml as a fast PR gate (v12-N-19).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="${ROOT}/Cargo.toml"
CHANGELOG="${ROOT}/CHANGELOG.md"

if [[ ! -r "${CARGO_TOML}" ]]; then
  echo "check_version_drift: cannot read ${CARGO_TOML}" >&2
  exit 2
fi
if [[ ! -r "${CHANGELOG}" ]]; then
  echo "check_version_drift: cannot read ${CHANGELOG}" >&2
  exit 2
fi

# (a) Extract `version = "x.y.z"` from the [workspace.package] table.
# We accept the first `version = "..."` line; the workspace pins one version
# for every member crate so the first match is authoritative.
VERSION="$(grep -E '^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' "${CARGO_TOML}" \
  | head -1 \
  | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"

if [[ -z "${VERSION}" ]]; then
  echo "check_version_drift: could not find a 'version = \"x.y.z\"' line in Cargo.toml" >&2
  exit 2
fi

# (b) Assert CHANGELOG.md contains a heading matching '## [x.y.z]' or '## x.y.z'.
if ! grep -E "^##[[:space:]]+(\[)?${VERSION//./\\.}(\])?([[:space:]]|$)" "${CHANGELOG}" >/dev/null; then
  echo "check_version_drift: CHANGELOG.md is missing a section for version ${VERSION}" >&2
  echo "  expected a heading like '## [${VERSION}]' or '## ${VERSION}'" >&2
  exit 1
fi

# (c) On a tag build, assert the tag's version equals Cargo's.
#     GITHUB_REF looks like 'refs/tags/v0.2.0' on tag pushes.
if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
  TAG_VERSION="${GITHUB_REF#refs/tags/v}"
  if [[ "${TAG_VERSION}" != "${VERSION}" ]]; then
    echo "check_version_drift: git tag v${TAG_VERSION} does not match Cargo.toml version ${VERSION}" >&2
    exit 1
  fi
fi

echo "check_version_drift: OK (version=${VERSION})"
exit 0
