#!/bin/sh
# Compile the static Sitrep binary and build a scratch container image.
# Usage: scripts/build-sitrep.sh [--demo]
# SITREP_BUILD=0 skips the work when the image is already present.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
demo=0
if [ "${1:-}" = "--demo" ]; then
  demo=1
fi
image=${SITREP_IMAGE:-sitrep}
runtime=${SITREP_RUNTIME:-}
if [ -z "$runtime" ]; then
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1; then
    runtime=docker
  else
    echo "sitrep: install podman or docker" >&2
    exit 1
  fi
fi
case "$runtime" in
  podman|docker) ;;
  *) echo "sitrep: runtime must be podman or docker" >&2; exit 1 ;;
esac
bin=$(command -v "$runtime")

if [ "${SITREP_BUILD:-1}" != "1" ]; then
  if "$bin" image inspect "$image" >/dev/null 2>&1; then
    exit 0
  fi
  echo "sitrep: image $image is not loaded; build it or unset SITREP_BUILD" >&2
  exit 1
fi

go_bin=${GO_BIN:-}
if [ -z "$go_bin" ]; then
  if command -v go >/dev/null 2>&1; then
    go_bin=$(command -v go)
  else
    home=${HOME:-}
    if [ -n "${SUDO_USER:-}" ]; then
      home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    if [ -n "$home" ]; then
      go_bin=$(find "$home/.local/share/mise/installs/go" -type f -path '*/bin/go' 2>/dev/null | sort | tail -n 1 || true)
    fi
  fi
fi
if [ -z "$go_bin" ] && [ -x /usr/local/go/bin/go ]; then
  go_bin=/usr/local/go/bin/go
fi
if [ -z "$go_bin" ]; then
  echo "sitrep: install Go 1.22 or newer to build the binary" >&2
  exit 1
fi

mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH:-amd64} GOPROXY=off GOTOOLCHAIN=local \
  "$go_bin" build -trimpath -ldflags '-s -w' -o dist/sitrep ./cmd/sitrep
if [ "$demo" = 1 ]; then
  ./dist/sitrep demo-data --out "$root/data"
fi
pull=--pull=false
if [ "$runtime" = podman ]; then
  pull=--pull=never
fi
"$bin" build $pull -t "$image" "$root"
echo "sitrep image $image"
