# Checklist console

A separate reader for checklist trees. It does not convert scans and it does not import into STIG Viewer. Point it at a directory of CKLB files and it counts what is already in them.

```text
completed_ckl/
  expected.json
  2026-q3/<benchmark-id>/<host>.cklb
  2026-q4/<benchmark-id>/<host>.cklb
```

`expected.json` lists the hosts that should have a checklist. A name on that list with no file is Missing. A file with no IP, an incomplete-snapshot note, or empty check text is Blocked. Anything else is Ready. Changed is the number of rule statuses that differ from the previous quarter for that same host and benchmark.

## Run

```sh
docker compose up --build
```

Open http://127.0.0.1:8787/

The image builds two quarters of test data: a small RHEL fleet and three switches. 2026 Q4 shows a missing switch, a host with no IP, an incomplete Cisco snapshot, and rule statuses that moved since 2026 Q3.

Appearance follows the browser until you choose Light or Dark. Paper, Inventory, and Signal are three treatments of the same page.
