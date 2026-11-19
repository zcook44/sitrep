#!/usr/bin/env python3
"""Write two quarters of checklist trees for the console.

The files are ordinary CKLB JSON. Quarters share rule ids so a later
read can see which statuses moved. One expected host is left out of
the later quarter on purpose.
"""

import argparse
import json
from pathlib import Path

LINUX = "linux"
NETWORK = "network"

HOSTS = [
    {"host": "rhel9-node1", "stig": "RHEL_9_STIG", "os": "RHEL 9", "kind": LINUX, "fqdn": "rhel9-node1.example.test", "ip": "192.0.2.21", "role": "node"},
    {"host": "rhel9-node2", "stig": "RHEL_9_STIG", "os": "RHEL 9", "kind": LINUX, "fqdn": "rhel9-node2.example.test", "ip": "192.0.2.22", "role": "node"},
    {"host": "rhel9-gui", "stig": "RHEL_9_STIG", "os": "RHEL 9", "kind": LINUX, "fqdn": "rhel9-gui.example.test", "ip": "192.0.2.23", "role": "gui"},
    {"host": "rhel8-edge", "stig": "RHEL_8_STIG", "os": "RHEL 8", "kind": LINUX, "fqdn": "rhel8-edge.example.test", "ip": "192.0.2.31", "role": "edge"},
    {"host": "rhel8-core", "stig": "RHEL_8_STIG", "os": "RHEL 8", "kind": LINUX, "fqdn": "rhel8-core.example.test", "ip": "192.0.2.32", "role": "core"},
    {"host": "rhel10-lab", "stig": "RHEL_10_STIG", "os": "RHEL 10", "kind": LINUX, "fqdn": "rhel10-lab.example.test", "ip": "192.0.2.41", "role": "lab"},
    {"host": "ios-xe-switch-01", "stig": "Cisco_IOS_XE_Switch_L2S_STIG", "os": "IOS-XE", "kind": NETWORK, "fqdn": "ios-xe-switch-01.example.test", "ip": "192.0.2.4", "role": "Access switch"},
    {"host": "ios-xe-switch-01", "stig": "Cisco_IOS_XE_Switch_NDM_STIG", "os": "IOS-XE", "kind": NETWORK, "fqdn": "ios-xe-switch-01.example.test", "ip": "192.0.2.4", "role": "Access switch"},
    {"host": "ios-switch-01", "stig": "Cisco_IOS_Switch_L2S_STIG", "os": "IOS", "kind": NETWORK, "fqdn": "ios-switch-01.example.test", "ip": "192.0.2.3", "role": "Access switch"},
    {"host": "nx-access-01", "stig": "Cisco_NX-OS_Switch_L2S_STIG", "os": "NX-OS", "kind": NETWORK, "fqdn": "nx-access-01.example.test", "ip": "192.0.2.12", "role": "Access switch"},
]

# status, severity, title, comment
def template(kind):
    base = 230200 if kind == LINUX else 220600
    rows = []
    plan = (
        [("open", "high")] * 3
        + [("open", "medium")] * 5
        + [("not_reviewed", "medium")] * 6
        + [("not_applicable", "low")] * 4
        + [("not_a_finding", "medium")] * 20
    )
    for index, (status, severity) in enumerate(plan):
        group = f"V-{base + index}"
        if status == "open" and severity == "high":
            comment = "Open. An SSG check failed on this host."
        elif status == "open":
            comment = "Open. The mapped check failed."
        elif status == "not_reviewed":
            comment = "Not Reviewed. No host value was recorded for this rule."
        elif status == "not_applicable":
            comment = "Not Applicable. This host does not run the feature."
        else:
            comment = "Not a Finding. The check passed on this host."
        rows.append({
            "group": group,
            "status": status,
            "severity": severity,
            "title": f"Control {group}",
            "comment": comment,
        })
    return rows


def apply_story(quarter, host, stig, rows):
    stories = {
        ("2026-q4", "rhel9-node1", "RHEL_9_STIG"): {
            "V-230200": ("not_a_finding", "high", "Not a Finding. Password hashing now matches the check."),
            "V-230218": ("open", "high", "Open. This host's sshd_config has PermitRootLogin yes. An SSG check failed."),
            "V-230203": ("not_a_finding", "medium", "Not a Finding. This host's sshd_config has ClientAliveInterval 600."),
            "V-230204": ("not_a_finding", "medium", "Not a Finding. The firewall service is enabled."),
            "V-230219": ("open", "medium", "Open. auditd is not running on this host."),
            "V-230205": ("not_reviewed", "medium", "Not Reviewed. The approved log host is a site fact."),
        },
        ("2026-q4", "rhel9-node2", "RHEL_9_STIG"): {
            "V-230203": ("not_a_finding", "medium", "Not a Finding. The prior finding was remediated on this host."),
            "V-230218": ("open", "medium", "Open. A local account lacks the required policy."),
            "V-230206": ("not_reviewed", "medium", "Not Reviewed. The organization-defined cipher list was not in the scan."),
        },
        ("2026-q4", "rhel9-gui", "RHEL_9_STIG"): {
            "V-230214": ("not_a_finding", "low", "Not a Finding. The graphical service is no longer installed."),
            "V-230218": ("open", "medium", "Open. Automatic updates are enabled."),
        },
        ("2026-q4", "rhel8-edge", "RHEL_8_STIG"): {
            "V-230218": ("open", "high", "Open. The edge host allows remote root login."),
        },
        ("2026-q4", "rhel10-lab", "RHEL_10_STIG"): {
            "V-230208": ("not_a_finding", "medium", "Not a Finding. The lab banner was replaced with the site notice."),
            "V-230219": ("open", "low", "Open. A world-writable path remains under /var/tmp."),
        },
        ("2026-q4", "ios-xe-switch-01", "Cisco_IOS_XE_Switch_L2S_STIG"): {
            "V-220618": ("open", "medium", "Open. BPDU Guard is missing on user-facing ports."),
        },
    }
    # Stable site-fact rows, present in both quarters.
    facts = {}
    if host == "rhel9-node1" and stig == "RHEL_9_STIG":
        facts["V-230214"] = ("not_reviewed", "medium", "Not Reviewed. The banner text is not in the scan. Record the required notice.")
    if host == "ios-xe-switch-01" and stig == "Cisco_IOS_XE_Switch_L2S_STIG":
        facts["V-220610"] = ("not_reviewed", "medium", "Not Reviewed. The approved management network is a site fact.")
    chosen = {}
    chosen.update(facts)
    chosen.update(stories.get((quarter, host, stig), {}))
    for row in rows:
        if row["group"] in chosen:
            status, severity, comment = chosen[row["group"]]
            row["status"] = status
            row["severity"] = severity
            row["comment"] = comment
    return rows


def checklist(spec, quarter, rows, note):
    name = {
        "RHEL_9_STIG": "RHEL 9 STIG",
        "RHEL_8_STIG": "RHEL 8 STIG",
        "RHEL_10_STIG": "RHEL 10 STIG",
        "Cisco_IOS_XE_Switch_L2S_STIG": "Cisco IOS XE Switch L2S STIG",
        "Cisco_IOS_XE_Switch_NDM_STIG": "Cisco IOS XE Switch NDM STIG",
        "Cisco_IOS_Switch_L2S_STIG": "Cisco IOS Switch L2S STIG",
        "Cisco_NX-OS_Switch_L2S_STIG": "Cisco NX-OS Switch L2S STIG",
    }[spec["stig"]]
    rules = []
    for row in rows:
        rules.append({
            "group_id": row["group"],
            "rule_id": row["group"].replace("V-", "SV-") + "r1_rule",
            "rule_title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "comments": row["comment"],
            "finding_details": row["comment"],
            "check_content": f"Review {row['group']} on {spec['host']}.",
        })
    target = {
        "host_name": spec["host"],
        "fqdn": spec["fqdn"],
        "ip_address": spec["ip"],
        "role": spec["role"],
        "comments": note,
    }
    return {
        "title": f"{spec['host']} - {name}",
        "cklb_version": "1.0",
        "target_data": target,
        "stigs": [{
            "stig_id": spec["stig"],
            "stig_name": name,
            "size": len(rules),
            "rules": rules,
        }],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.out
    root.mkdir(parents=True, exist_ok=True)
    expected = {"2026-q3": [], "2026-q4": []}
    for spec in HOSTS:
        for quarter in ("2026-q3", "2026-q4"):
            expected[quarter].append({
                "host": spec["host"],
                "benchmark_id": spec["stig"],
                "os": spec["os"],
            })
            mutated = dict(spec)
            note = ""
            skip = False
            if quarter == "2026-q4" and spec["host"] == "rhel8-edge" and spec["stig"] == "RHEL_8_STIG":
                mutated["ip"] = ""
            if quarter == "2026-q4" and spec["stig"] == "Cisco_IOS_XE_Switch_NDM_STIG":
                note = "Snapshot has no closing end."
            if quarter == "2026-q4" and spec["host"] == "nx-access-01":
                skip = True
            if skip:
                continue
            rows = apply_story(quarter, spec["host"], spec["stig"], template(spec["kind"]))
            folder = root / quarter / spec["stig"]
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"{spec['host']}.cklb"
            path.write_text(json.dumps(checklist(mutated, quarter, rows, note), indent=2) + "\n", encoding="utf-8")
    (root / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    print(f"wrote checklist tree at {root}")


if __name__ == "__main__":
    main()
