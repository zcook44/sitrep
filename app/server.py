#!/usr/bin/env python3
"""Read a checklist tree and serve the posture console.

The process does not score hosts. It counts statuses already stored in
CKLB files and compares a quarter with the previous one.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(os.environ.get("CHECKLIST_ROOT", "/data")).resolve()
STATIC = Path(__file__).resolve().parent / "static"
PORT = int(os.environ.get("PORT", "8780"))

BENCHMARK_NAMES = {
    "RHEL_10_STIG": "RHEL 10",
    "RHEL_9_STIG": "RHEL 9",
    "RHEL_8_STIG": "RHEL 8",
    "RHEL_7_STIG": "RHEL 7",
    "Cisco_IOS_XE_Switch_L2S_STIG": "IOS-XE L2S",
    "Cisco_IOS_XE_Switch_NDM_STIG": "IOS-XE NDM",
    "Cisco_IOS_Switch_L2S_STIG": "IOS L2S",
    "Cisco_NX-OS_Switch_L2S_STIG": "NX-OS L2S",
}

SITE_FACT = ("banner", "organization-defined", "site fact", "approved")


def quarter_label(quarter):
    year, part = quarter.split("-q", 1)
    return f"{year} Q{part}"


def quarter_key(quarter):
    year, part = quarter.split("-q", 1)
    return int(year), int(part)


def load_cklb(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    stig = document["stigs"][0]
    target = document.get("target_data") or {}
    rules = []
    for rule in stig.get("rules") or []:
        rules.append({
            "group": rule.get("group_id") or "",
            "severity": (rule.get("severity") or "").lower(),
            "status": rule.get("status") or "",
            "comment": (rule.get("comments") or "").strip(),
            "check": (rule.get("check_content") or "").strip(),
            "title": rule.get("rule_title") or "",
        })
    return {
        "benchmark_id": stig.get("stig_id") or "",
        "benchmark": BENCHMARK_NAMES.get(stig.get("stig_id"), stig.get("stig_name") or stig.get("stig_id") or ""),
        "size": stig.get("size"),
        "host": target.get("host_name") or path.stem,
        "fqdn": target.get("fqdn") or "",
        "ip": target.get("ip_address") or "",
        "role": target.get("role") or "",
        "note": (target.get("comments") or "").strip(),
        "rules": rules,
        "path": str(path.relative_to(ROOT)),
    }


def discover():
    found = {}
    if not ROOT.is_dir():
        return found
    for path in sorted(ROOT.glob("*/*/*.cklb")):
        quarter = path.relative_to(ROOT).parts[0]
        if quarter.startswith("."):
            continue
        loaded = load_cklb(path)
        found[(quarter, loaded["host"], loaded["benchmark_id"])] = loaded
    return found


def expected_rows():
    path = ROOT / "expected.json"
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for quarter, items in document.items():
        for item in items:
            rows.append({
                "quarter": quarter,
                "host": item["host"],
                "benchmark_id": item["benchmark_id"],
                "os": item.get("os") or "",
            })
    return rows


def counts(rules):
    tally = {"open": 0, "not_reviewed": 0, "not_applicable": 0, "not_a_finding": 0}
    cat1 = 0
    for rule in rules:
        status = rule["status"]
        if status in tally:
            tally[status] += 1
        if status == "open" and rule["severity"] == "high":
            cat1 += 1
    return tally, cat1


def blocked_reason(loaded):
    if loaded["size"] not in (None, len(loaded["rules"])):
        return "Rule count does not match the checklist size."
    if any(not rule["check"] for rule in loaded["rules"]):
        return "Check text is empty on at least one rule."
    note = loaded["note"].lower()
    if "no closing end" in note or "incomplete" in note:
        return loaded["note"]
    if not loaded["ip"]:
        return "Target page has no IP."
    return ""


def highlights(current, previous):
    lines = []
    if current is None:
        if previous is None:
            lines.append("No checklist in this tree.")
        else:
            lines.append(f"Checklist was present in {quarter_label(previous['quarter'])} and is absent from this quarter.")
        return lines
    reason = blocked_reason(current)
    if reason:
        lines.append(f"Blocked: {reason}")
    if previous is not None:
        prior = {rule["group"]: rule for rule in previous["rules"]}
        changes = []
        for rule in current["rules"]:
            old = prior.get(rule["group"])
            if old and old["status"] != rule["status"]:
                changes.append(rule | {"old": old["status"]})
        for rule in changes[:6]:
            lines.append(
                f"Changed: {rule['group']} moved from {words(rule['old'])} to {words(rule['status'])}. {rule['comment']}"
            )
    cat1 = [rule for rule in current["rules"] if rule["status"] == "open" and rule["severity"] == "high"]
    for rule in cat1[:4]:
        lines.append(f"CAT I open: {rule['group']}. {rule['comment']}")
    facts = [
        rule for rule in current["rules"]
        if rule["status"] == "not_reviewed" and any(word in rule["comment"].lower() for word in SITE_FACT)
    ]
    for rule in facts[:3]:
        lines.append(f"Needs a site fact: {rule['group']}. {rule['comment']}")
    if not lines:
        lines.append("No status changes, CAT I opens, or site facts on this checklist.")
    return lines


def words(status):
    return {
        "open": "Open",
        "not_a_finding": "Not a finding",
        "not_reviewed": "Not reviewed",
        "not_applicable": "Not applicable",
    }.get(status, status)


def changed_count(current, previous):
    if current is None or previous is None:
        return None
    prior = {rule["group"]: rule["status"] for rule in previous["rules"]}
    return sum(1 for rule in current["rules"] if prior.get(rule["group"], rule["status"]) != rule["status"])


def posture():
    found = discover()
    quarters = sorted({key[0] for key in found} | {row["quarter"] for row in expected_rows()}, key=quarter_key)
    previous_of = {}
    for index, quarter in enumerate(quarters):
        previous_of[quarter] = quarters[index - 1] if index else None
    slots = {}
    for row in expected_rows():
        slots[(row["quarter"], row["host"], row["benchmark_id"])] = row
    for key, loaded in found.items():
        slots.setdefault(key, {
            "quarter": key[0],
            "host": loaded["host"],
            "benchmark_id": loaded["benchmark_id"],
            "os": "",
        })
    records = []
    for key, slot in sorted(slots.items(), key=lambda item: (quarter_key(item[0][0]), item[0][1], item[0][2])):
        quarter, host, benchmark_id = key
        loaded = found.get(key)
        previous = None
        prior_quarter = previous_of.get(quarter)
        if prior_quarter:
            previous_loaded = found.get((prior_quarter, host, benchmark_id))
            if previous_loaded:
                previous = previous_loaded | {"quarter": prior_quarter}
        benchmark = BENCHMARK_NAMES.get(benchmark_id, loaded["benchmark"] if loaded else benchmark_id)
        os_name = slot.get("os") or benchmark
        if loaded is None:
            records.append({
                "id": "|".join(key),
                "host": host,
                "quarter": quarter_label(quarter),
                "quarter_id": quarter,
                "benchmark": benchmark,
                "benchmark_id": benchmark_id,
                "os": os_name,
                "handoff": "Missing",
                "open": None,
                "cat1": None,
                "not_reviewed": None,
                "not_applicable": None,
                "not_a_finding": None,
                "changed": None,
                "path": "",
                "identity": "",
                "lines": highlights(None, previous),
            })
            continue
        tally, cat1 = counts(loaded["rules"])
        reason = blocked_reason(loaded)
        identity = " · ".join(part for part in (loaded["fqdn"], loaded["ip"], loaded["role"]) if part)
        records.append({
            "id": "|".join(key),
            "host": host,
            "quarter": quarter_label(quarter),
            "quarter_id": quarter,
            "benchmark": benchmark,
            "benchmark_id": benchmark_id,
            "os": os_name,
            "handoff": "Blocked" if reason else "Ready",
            "open": tally["open"],
            "cat1": cat1,
            "not_reviewed": tally["not_reviewed"],
            "not_applicable": tally["not_applicable"],
            "not_a_finding": tally["not_a_finding"],
            "changed": changed_count(loaded, previous),
            "path": loaded["path"],
            "identity": identity,
            "lines": highlights(loaded, previous),
        })
    return {"root": str(ROOT), "rows": records}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/posture":
            body = json.dumps(posture()).encode("utf-8")
            self.respond(200, "application/json; charset=utf-8", body)
            return
        if path == "/api/health":
            self.respond(200, "application/json", b'{"ok":true}')
            return
        if path in ("/", "/index.html"):
            self.respond(200, "text/html; charset=utf-8", (STATIC / "index.html").read_bytes())
            return
        self.respond(404, "text/plain; charset=utf-8", b"Not found\n")

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"checklist console reading {ROOT} on {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
