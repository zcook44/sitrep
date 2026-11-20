#!/bin/sh
# Run Sitrep with docker or podman.
# Usage: scripts/run-sitrep.sh [docker|podman]
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
runtime=${1:-}
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

image=${SITREP_IMAGE:-sitrep}
envfile=${SITREP_ENV:-$root/config/console.env}
data=${CHECKLIST_DIR:-$root/data}
hostport=${HOST_PORT:-8787}
name=${SITREP_NAME:-sitrep}
label=
if [ "$runtime" = podman ]; then
  label=,Z
fi

if [ ! -d "$data" ]; then
  echo "sitrep: set CHECKLIST_DIR to the root of the checklist tree" >&2
  exit 1
fi

if [ "${SITREP_BUILD:-}" = "1" ] || ! "$runtime" image inspect "$image" >/dev/null 2>&1; then
  "$runtime" build -t "$image" "$root"
fi

"$runtime" rm -f "$name" >/dev/null 2>&1 || true
set -- run --name "$name" -d \
  --env-file "$envfile" \
  -p "${hostport}:8780" \
  -v "${data}:/data:ro${label}"
if [ -f /etc/localtime ]; then
  set -- "$@" -v "/etc/localtime:/host/localtime:ro${label}"
fi
if [ -S /run/dbus/system_bus_socket ]; then
  set -- "$@" -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket
fi
if [ -d /run/systemd/seats ]; then
  set -- "$@" -v "/run/systemd:/run/systemd:ro${label}"
fi
"$runtime" "$@" "$image"
echo "sitrep on http://127.0.0.1:${hostport}/"
