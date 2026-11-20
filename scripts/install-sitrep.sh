#!/bin/sh
# Build Sitrep and install a systemd service that reads a checklist tree.
# Usage: sudo scripts/install-sitrep.sh [--runtime podman|docker] [--port N] CHECKLIST_ROOT
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
runtime=
port=${HOST_PORT:-8787}
checklist=

usage() {
  echo "usage: install-sitrep.sh [--runtime podman|docker] [--port N] CHECKLIST_ROOT" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --runtime)
      [ "$#" -ge 2 ] || usage
      runtime=$2
      shift 2
      ;;
    --port)
      [ "$#" -ge 2 ] || usage
      port=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      usage
      ;;
    *)
      if [ -n "$checklist" ]; then
        usage
      fi
      checklist=$1
      shift
      ;;
  esac
done
if [ "$#" -gt 0 ] || [ -z "$checklist" ]; then
  usage
fi

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
case "$port" in
  ''|*[!0-9]*) echo "sitrep: port must be a number" >&2; exit 1 ;;
esac

if [ ! -d "$checklist" ]; then
  echo "sitrep: checklist root is not a directory: $checklist" >&2
  exit 1
fi
checklist=$(CDPATH= cd -- "$checklist" && pwd)
case "$checklist" in
  *\"*|*\$*|*\`*)
    echo "sitrep: checklist path contains a quote or a dollar sign" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ] && [ "${SITREP_SKIP_SYSTEMD:-}" != "1" ]; then
  echo "sitrep: run as root so the service can start at boot" >&2
  exit 1
fi

image=${SITREP_IMAGE:-sitrep}
unit=${SITREP_UNIT:-/etc/systemd/system/sitrep.service}
etcdir=${SITREP_ETC:-/etc/sitrep}
bin=$(command -v "$runtime")
label=
if [ "$runtime" = podman ]; then
  label=,Z
fi

if [ "${SITREP_BUILD:-1}" = "1" ]; then
  "$bin" build -t "$image" "$root"
elif ! "$bin" image inspect "$image" >/dev/null 2>&1; then
  echo "sitrep: image $image is not loaded; build it or unset SITREP_BUILD" >&2
  exit 1
fi

mkdir -p "$etcdir" "$(dirname "$unit")"
if [ ! -f "$etcdir/console.env" ]; then
  cp "$root/config/console.env" "$etcdir/console.env"
fi

after="network-online.target"
wants="network-online.target"
if [ "$runtime" = docker ]; then
  after="$after docker.service"
  wants="$wants docker.service"
fi

cat > "$unit" << EOF
[Unit]
Description=Sitrep
After=$after
Wants=$wants

[Service]
Type=simple
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
ExecStartPre=-$bin rm -f sitrep
ExecStart=$bin run --rm --name sitrep --env-file $etcdir/console.env -p ${port}:8780 -v "$checklist:/data:ro${label}" -v /etc/localtime:/host/localtime:ro $image
ExecStop=$bin stop -t 10 sitrep

[Install]
WantedBy=multi-user.target
EOF

if [ "${SITREP_SKIP_SYSTEMD:-}" = "1" ]; then
  echo "sitrep: wrote $unit"
  exit 0
fi

systemctl daemon-reload
systemctl enable sitrep
systemctl restart sitrep
echo "sitrep service enabled on port ${port}, reading ${checklist}"
