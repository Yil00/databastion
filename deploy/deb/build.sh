#!/usr/bin/env bash
# Builds the databastion-agent .deb from an agent binary (deploy/README.md, "Agent .deb").
#
#   deploy/deb/build.sh --binary PATH --arch amd64|arm64 --version X.Y.Z[-pre] --out DIR
#
# The binary is the one of the published agent image (publish.yml copies it out of the signed
# image) or of a local `docker build agent/`. The package is reproducible: same binary, version
# and commit => same bytes (SOURCE_DATE_EPOCH defaults to the commit time of HEAD).
# Requires: nfpm (deploy/deb/install-nfpm.sh), readelf (binutils), git.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
usage() { echo "usage: $0 --binary PATH --arch amd64|arm64 --version X.Y.Z[-pre] --out DIR" >&2; exit 64; }

binary="" arch="" version="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --arch) arch="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$binary" ] && [ -n "$arch" ] && [ -n "$version" ] && [ -n "$out" ] || usage
case "$arch" in
  amd64) machine="Advanced Micro Devices X86-64" ;;
  arm64) machine="AArch64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 64 ;;
esac
# Same rule as publish.yml (RELEASE.md: SemVer, no `v` prefix).
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "invalid version: $version" >&2; exit 64
fi
[ -f "$binary" ] || { echo "no such binary: $binary" >&2; exit 1; }
NFPM="${NFPM:-nfpm}"
command -v "$NFPM" >/dev/null || { echo "nfpm not found (deploy/deb/install-nfpm.sh)" >&2; exit 1; }

# The binary must be a Linux ELF of the package architecture.
header="$(readelf -h "$binary")"
grep -q "Machine: *${machine}\$" <<<"$header" \
  || { echo "$binary is not a Linux ${arch} executable" >&2; exit 1; }

# glibc floor from the binary's versioned symbols (the agent is built on Debian 12, glibc 2.36).
glibc="$(readelf -V --wide "$binary" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)"
[ -n "$glibc" ] || { echo "no GLIBC symbol version found in $binary" >&2; exit 1; }

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}"
export DEB_ARCH="$arch" DEB_VERSION="$version" DEB_LIBC_DEPENDS="libc6 (>= ${glibc})"
AGENT_BINARY="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
export AGENT_BINARY AGENT_EXAMPLE_CONFIG="$ROOT/agent/agent.example.yaml"

mkdir -p "$out"
# The file name keeps the SemVer version (a pre-release `~` would be rewritten by GitHub).
target="$(cd "$out" && pwd)/databastion-agent_${version}_${arch}.deb"
rm -f "$target"
# nfpm resolves the relative sources (unit, scripts, copyright) from its working directory.
(cd "$HERE" && umask 022 && "$NFPM" package --config nfpm.yaml --packager deb --target "$target" >&2)
echo "$target"
