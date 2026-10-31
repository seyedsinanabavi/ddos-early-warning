#!/usr/bin/env bash
# Builds a self-contained Linux amd64 package: static binary, configs, systemd
# unit, installer and docs. The target host needs no Go toolchain and no
# network access. The build machine needs Go and the module cache (or network
# access to fetch modules) once, at build time.
#
#   ./scripts/package-offline.sh
#   -> dist/ddos-early-warning-<version>-linux-amd64.tar.gz (+ .sha256)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v go >/dev/null || { echo "go toolchain is required to build" >&2; exit 1; }

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
NAME="ddos-early-warning-${VERSION}-linux-amd64"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/$NAME"

mkdir -p "$PKG/bin" "$PKG/configs" "$PKG/deploy/systemd" "$PKG/scripts" "$PKG/docs"

# CGO off gives a static binary that runs on any recent Linux distribution.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
  -o "$PKG/bin/ddos-ew" ./cmd/ddos-ew

cp configs/collector.yaml configs/detection.yaml configs/alerts.yaml "$PKG/configs/"
cp deploy/systemd/ddos-ew.service "$PKG/deploy/systemd/"
cp scripts/install.sh "$PKG/scripts/"
[[ -f README.md ]] && cp README.md "$PKG/"
if [[ -d docs ]]; then
  cp docs/*.md "$PKG/docs/"
fi

(
  cd "$PKG"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

mkdir -p dist
tar -C "$STAGE" -czf "dist/$NAME.tar.gz" "$NAME"
(
  cd dist
  sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256"
)
echo "built dist/$NAME.tar.gz"