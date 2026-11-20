// Package demo writes two quarters of checklist files so Sitrep can be opened before a real tree exists.
package demo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	linuxKind   = "linux"
	networkKind = "network"
)

type spec struct {
	Host, Stig, OS, Kind, FQDN, IP, Role string
}

type row struct {
	Group, Status, Severity, Title, Comment string
}

var releases = map[string][2]int{
	"RHEL_9_STIG":                  {2, 5},
	"RHEL_8_STIG":                  {2, 2},
	"RHEL_10_STIG":                 {1, 1},
	"Cisco_IOS_XE_Switch_L2S_STIG": {3, 2},
	"Cisco_IOS_XE_Switch_NDM_STIG": {3, 6},
	"Cisco_IOS_Switch_L2S_STIG":    {3, 3},
	"Cisco_NX-OS_Switch_L2S_STIG":  {3, 4},
}

var names = map[string]string{
	"RHEL_9_STIG":                  "RHEL 9 STIG",
	"RHEL_8_STIG":                  "RHEL 8 STIG",
	"RHEL_10_STIG":                 "RHEL 10 STIG",
	"Cisco_IOS_XE_Switch_L2S_STIG": "Cisco IOS XE Switch L2S STIG",
	"Cisco_IOS_XE_Switch_NDM_STIG": "Cisco IOS XE Switch NDM STIG",
	"Cisco_IOS_Switch_L2S_STIG":    "Cisco IOS Switch L2S STIG",
	"Cisco_NX-OS_Switch_L2S_STIG":  "Cisco NX-OS Switch L2S STIG",
}

var hosts = []spec{
	{"rhel9-node1", "RHEL_9_STIG", "RHEL 9", linuxKind, "rhel9-node1.example.test", "192.0.2.21", "node"},
	{"rhel9-node2", "RHEL_9_STIG", "RHEL 9", linuxKind, "rhel9-node2.example.test", "192.0.2.22", "node"},
	{"rhel9-gui", "RHEL_9_STIG", "RHEL 9", linuxKind, "rhel9-gui.example.test", "192.0.2.23", "gui"},
	{"rhel8-edge", "RHEL_8_STIG", "RHEL 8", linuxKind, "rhel8-edge.example.test", "192.0.2.31", "edge"},
	{"rhel8-core", "RHEL_8_STIG", "RHEL 8", linuxKind, "rhel8-core.example.test", "192.0.2.32", "core"},
	{"rhel10-lab", "RHEL_10_STIG", "RHEL 10", linuxKind, "rhel10-lab.example.test", "192.0.2.41", "lab"},
	{"ios-xe-switch-01", "Cisco_IOS_XE_Switch_L2S_STIG", "IOS-XE", networkKind, "ios-xe-switch-01.example.test", "192.0.2.4", "Access switch"},
	{"ios-xe-switch-01", "Cisco_IOS_XE_Switch_NDM_STIG", "IOS-XE", networkKind, "ios-xe-switch-01.example.test", "192.0.2.4", "Access switch"},
	{"ios-switch-01", "Cisco_IOS_Switch_L2S_STIG", "IOS", networkKind, "ios-switch-01.example.test", "192.0.2.3", "Access switch"},
	{"nx-access-01", "Cisco_NX-OS_Switch_L2S_STIG", "NX-OS", networkKind, "nx-access-01.example.test", "192.0.2.12", "Access switch"},
}

// Write creates the demo tree at dir.
func Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	expected := map[string][]map[string]string{"2026-q3": {}, "2026-q4": {}}
	for _, item := range hosts {
		for _, quarter := range []string{"2026-q3", "2026-q4"} {
			version, release := releases[item.Stig][0], releases[item.Stig][1]
			expected[quarter] = append(expected[quarter], map[string]string{
				"host": item.Host, "benchmark_id": item.Stig, "os": item.OS,
				"release": fmt.Sprintf("V%dR%d", version, release),
			})
			current := item
			note := ""
			if quarter == "2026-q4" && item.Host == "rhel8-edge" && item.Stig == "RHEL_8_STIG" {
				current.IP = ""
			}
			if quarter == "2026-q4" && item.Stig == "Cisco_IOS_XE_Switch_NDM_STIG" {
				note = "Snapshot has no closing end."
			}
			if quarter == "2026-q4" && item.Host == "nx-access-01" {
				continue
			}
			body, err := json.MarshalIndent(checklist(current, version, release, applyStory(quarter, item.Host, item.Stig, template(item.Kind)), note), "", "  ")
			if err != nil {
				return err
			}
			folder := filepath.Join(dir, quarter, item.Stig)
			if err := os.MkdirAll(folder, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(folder, item.Host+".cklb"), append(body, '\n'), 0o644); err != nil {
				return err
			}
		}
	}
	raw, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "expected.json"), append(raw, '\n'), 0o644)
}

func template(kind string) []row {
	base := 230200
	if kind == networkKind {
		base = 220600
	}
	plan := append(repeat("open", "high", 3), repeat("open", "medium", 5)...)
	plan = append(plan, repeat("not_reviewed", "medium", 6)...)
	plan = append(plan, repeat("not_applicable", "low", 4)...)
	plan = append(plan, repeat("not_a_finding", "medium", 20)...)
	rows := make([]row, 0, len(plan))
	for index, item := range plan {
		group := fmt.Sprintf("V-%d", base+index)
		comment := "Not a Finding. The check passed on this host."
		switch {
		case item[0] == "open" && item[1] == "high":
			comment = "Open. An SSG check failed on this host."
		case item[0] == "open":
			comment = "Open. The mapped check failed."
		case item[0] == "not_reviewed":
			comment = "Not Reviewed. No host value was recorded for this rule."
		case item[0] == "not_applicable":
			comment = "Not Applicable. This host does not run the feature."
		}
		rows = append(rows, row{Group: group, Status: item[0], Severity: item[1], Title: "Control " + group, Comment: comment})
	}
	return rows
}

func repeat(status, severity string, n int) [][2]string {
	out := make([][2]string, n)
	for i := range out {
		out[i] = [2]string{status, severity}
	}
	return out
}

func applyStory(quarter, host, stig string, rows []row) []row {
	type change struct{ status, severity, comment string }
	chosen := map[string]change{}
	if host == "rhel9-node1" && stig == "RHEL_9_STIG" {
		chosen["V-230214"] = change{"not_reviewed", "medium", "Not Reviewed. The banner text is not in the scan. Record the required notice."}
	}
	if host == "ios-xe-switch-01" && stig == "Cisco_IOS_XE_Switch_L2S_STIG" {
		chosen["V-220610"] = change{"not_reviewed", "medium", "Not Reviewed. The approved management network is a site fact."}
	}
	stories := map[string]map[string]change{
		"2026-q4|rhel9-node1|RHEL_9_STIG": {
			"V-230200": {"not_a_finding", "high", "Not a Finding. Password hashing now matches the check."},
			"V-230218": {"open", "high", "Open. This host's sshd_config has PermitRootLogin yes. An SSG check failed."},
			"V-230203": {"not_a_finding", "medium", "Not a Finding. This host's sshd_config has ClientAliveInterval 600."},
			"V-230204": {"not_a_finding", "medium", "Not a Finding. The firewall service is enabled."},
			"V-230219": {"open", "medium", "Open. auditd is not running on this host."},
			"V-230205": {"not_reviewed", "medium", "Not Reviewed. The approved log host is a site fact."},
		},
		"2026-q4|rhel9-node2|RHEL_9_STIG": {
			"V-230203": {"not_a_finding", "medium", "Not a Finding. The prior finding was remediated on this host."},
			"V-230218": {"open", "medium", "Open. A local account lacks the required policy."},
			"V-230206": {"not_reviewed", "medium", "Not Reviewed. The organization-defined cipher list was not in the scan."},
		},
		"2026-q4|rhel9-gui|RHEL_9_STIG": {
			"V-230214": {"not_a_finding", "low", "Not a Finding. The graphical service is no longer installed."},
			"V-230218": {"open", "medium", "Open. Automatic updates are enabled."},
		},
		"2026-q4|rhel8-edge|RHEL_8_STIG": {
			"V-230218": {"open", "high", "Open. The edge host allows remote root login."},
		},
		"2026-q4|rhel10-lab|RHEL_10_STIG": {
			"V-230208": {"not_a_finding", "medium", "Not a Finding. The lab banner was replaced with the site notice."},
			"V-230219": {"open", "low", "Open. A world-writable path remains under /var/tmp."},
		},
		"2026-q4|ios-xe-switch-01|Cisco_IOS_XE_Switch_L2S_STIG": {
			"V-220618": {"open", "medium", "Open. BPDU Guard is missing on user-facing ports."},
		},
	}
	for group, item := range stories[quarter+"|"+host+"|"+stig] {
		chosen[group] = item
	}
	for i := range rows {
		if item, ok := chosen[rows[i].Group]; ok {
			rows[i].Status = item.status
			rows[i].Severity = item.severity
			rows[i].Comment = item.comment
		}
	}
	return rows
}

func checklist(item spec, version, release int, rows []row, note string) map[string]any {
	rules := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, map[string]string{
			"group_id": row.Group, "rule_id": "SV-" + row.Group[2:] + "r1_rule", "rule_title": row.Title,
			"severity": row.Severity, "status": row.Status, "comments": row.Comment,
			"finding_details": row.Comment, "check_content": fmt.Sprintf("Review %s on %s.", row.Group, item.Host),
		})
	}
	return map[string]any{
		"title": item.Host + " - " + names[item.Stig], "cklb_version": "1.0",
		"target_data": map[string]string{
			"host_name": item.Host, "fqdn": item.FQDN, "ip_address": item.IP, "role": item.Role, "comments": note,
		},
		"stigs": []any{map[string]any{
			"stig_id": item.Stig, "stig_name": names[item.Stig], "version": fmt.Sprintf("%d", version),
			"release_info": fmt.Sprintf("Release: %d Benchmark Date: 30 Sep 2026", release),
			"size":         len(rules), "rules": rules,
		}},
	}
}
