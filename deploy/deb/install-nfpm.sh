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
# Go toolchain used to build it (nfpm needs go >= 1.26.4); fetched and verified by the local `go`
# (1.21 or later) through the same checksum database.
GO_TOOLCHAIN="go1.26.8"

dir="${1:-.bin}"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
# The checksum database must not be disabled or bypassed by the environment.
GOBIN="$dir" GOTOOLCHAIN="$GO_TOOLCHAIN" GOSUMDB=sum.golang.org GOPRIVATE="" GONOSUMDB="" GOINSECURE="" GOFLAGS="" \
  go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" >&2
got="$(GOTOOLCHAIN="$GO_TOOLCHAIN" go version -m "$dir/nfpm" \
  | awk '$1 == "mod" && $2 == "github.com/goreleaser/nfpm/v2" {print $3 " " $4}')"
if [ "$got" != "${NFPM_VERSION} ${NFPM_MODULE_SUM}" ]; then
  rm -f "$dir/nfpm"
  echo "nfpm module mismatch: got '$got', expected '${NFPM_VERSION} ${NFPM_MODULE_SUM}' (binary deleted)" >&2
  exit 1
fi
echo "$dir/nfpm"
