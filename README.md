# Sitrep

Sitrep is the reader for a checklist tree. Ceasefire's `docket` writes the CKLB files. `checkmate` can edit a site fact the scan cannot see. Sitrep mounts the tree and counts what is already in the files. It does not convert scans, write checklists, or import into STIG Viewer. Security still opens the same CKLB files in STIG Viewer.

The page is newest quarter first. List, Compare, and Attention are three views of the same rows. A bar under each host splits Open, Not reviewed, Not applicable, and Not a finding by count. Filter cards start collapsed. The benchmark filter shows the STIG version and release, such as V2R5. Appearance follows the browser until you choose Light or Dark.

The header shows the network Sitrep is running on, the date, and the user viewing the page.

## Dataflow

```mermaid
flowchart LR
  scan["Saved scan or running config"] --> docket["docket"]
  docket --> tree["Checklist tree"]
  checkmate["checkmate"] -.-> tree
  tree --> sitrep["Sitrep"]
  tree --> viewer["STIG Viewer"]
  sitrep --> browser["Browser"]
```

`docket` writes a `.cklb` and a `.cklb.provenance.json` sidecar into the tree. `checkmate` is optional and edits the CKLB in place. Sitrep and STIG Viewer both read that tree. Sitrep does not hand a file to STIG Viewer, and nothing writes back from the browser.

Mount any directory. Every `.cklb` under it is a row, at any depth. A directory named `2026-q4`, `Q4_2026`, or `2026Q4` becomes the quarter. Host, benchmark, and version come from the checklist. When two files describe the same host and benchmark in one quarter, Sitrep keeps the newer file.

An optional `expected.json` at the root of the tree lists hosts that should have a file. A name on that list with no `.cklb` is Missing. A file with no IP, an incomplete-snapshot note, or empty check text is Blocked. Anything else is Ready. Changed is the number of rule statuses that differ from the previous quarter for that same host and benchmark.

## Install the demo

The demo image contains two quarters of test data.

```sh
docker compose up --build
```

`podman compose up --build` uses the same file. Open http://127.0.0.1:8787/

2026 Q4 in the demo shows a missing switch, a host with no IP, an incomplete Cisco snapshot, and rule statuses that moved since 2026 Q3.

## Install on a host

`install-sitrep.sh` builds the image, mounts the checklist tree, and installs a systemd service that starts at boot. Run it as root. The argument is the checklist root. Podman is used when it is installed.

```sh
sudo scripts/install-sitrep.sh /private/checklists
```

`--runtime docker` selects Docker. `--port` changes the published port. The process inside the container listens on `8780`. The service is `sitrep`:

```sh
systemctl status sitrep
systemctl restart sitrep
```

The unit is `/etc/systemd/system/sitrep.service`. Settings are `/etc/sitrep/console.env`, copied from `config/console.env` on the first install. Set `CHECKLIST_DOMAIN` there when the header should name the network. A later install leaves that file in place.

On a disconnected host, load the image first and skip the build:

```sh
sudo SITREP_BUILD=0 scripts/install-sitrep.sh /private/checklists
```

`scripts/run-sitrep.sh` still runs one container in the foreground of the container tool, without installing a service. `CHECKLIST_DIR` is the tree on the host.

## Disconnected host

Build where the base image is already present, then carry the tar:

```sh
docker build -t sitrep .
docker save -o sitrep.tar sitrep
```

Use `podman` the same way (`podman save` and `podman load`). On the disconnected host:

```sh
docker load -i sitrep.tar
sudo SITREP_BUILD=0 scripts/install-sitrep.sh /private/checklists
```

`podman load` is the same step. `SITREP_BUILD=0` keeps the host from trying to pull a base image.
