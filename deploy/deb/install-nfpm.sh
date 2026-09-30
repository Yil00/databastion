#!/usr/bin/env bash
# Installs the pinned nfpm (MIT) into DIR (default: ./.bin) and prints its path.
#
#   deploy/deb/install-nfpm.sh [DIR]
#
# Built from source with `go install` at a fixed version: the Go toolchain verifies the module and
# every dependency against the Go checksum database (sum.golang.org), and the module hash is then
# compared with the pin below. Bump both together (Dependabot does not track this file):
#   go install github.com/goreleaser/nfpm/v2/cmd/nfpm@vX.Y.Z && go version -m "$(go env GOPATH)/bin/nfpm"
set -euo pipefail

NFPM_VERSION="v2.47.0"
NFPM_MODULE_SUM="h1:0bioJAjWaMPntgDqynP4ze0Wt4zYqYSFJ5/BBy9XIGI="

dir="${1:-.bin}"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
# The checksum database must not be disabled or bypassed by the environment.
GOBIN="$dir" GOSUMDB=sum.golang.org GOPRIVATE="" GONOSUMDB="" GOINSECURE="" GOFLAGS="" \
  go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" >&2
got="$(go version -m "$dir/nfpm" | awk '$1 == "mod" && $2 == "github.com/goreleaser/nfpm/v2" {print $3 " " $4}')"
if [ "$got" != "${NFPM_VERSION} ${NFPM_MODULE_SUM}" ]; then
  echo "nfpm module mismatch: got '$got', expected '${NFPM_VERSION} ${NFPM_MODULE_SUM}'" >&2
  exit 1
fi
echo "$dir/nfpm"
