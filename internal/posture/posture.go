// Package posture counts checklist statuses already stored in CKLB files.
package posture

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var quarterDirs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(?P<year>\d{4})-q(?P<part>\d+)$`),
	regexp.MustCompile(`(?i)^Q(?P<part>\d+)_(?P<year>\d{4})$`),
	regexp.MustCompile(`(?i)^(?P<year>\d{4})Q(?P<part>\d+)$`),
}

var (
	versionRelease = regexp.MustCompile(`(?i)V\s*(\d+)\s*R\s*(\d+)`)
	releaseNumber  = regexp.MustCompile(`(?i)Release:\s*(\d+)`)
	versionNumber  = regexp.MustCompile(`(?i)^V?\s*(\d+)$`)
	rhelOS         = regexp.MustCompile(`^RHEL_(\d+)_STIG$`)
)

var benchmarkNames = map[string]string{
	"RHEL_10_STIG":                 "RHEL 10",
	"RHEL_9_STIG":                  "RHEL 9",
	"RHEL_8_STIG":                  "RHEL 8",
	"RHEL_7_STIG":                  "RHEL 7",
	"Cisco_IOS_XE_Switch_L2S_STIG": "IOS-XE L2S",
	"Cisco_IOS_XE_Switch_NDM_STIG": "IOS-XE NDM",
	"Cisco_IOS_Switch_L2S_STIG":    "IOS L2S",
	"Cisco_NX-OS_Switch_L2S_STIG":  "NX-OS L2S",
}

var siteFact = []string{"banner", "organization-defined", "site fact", "approved"}

// Payload is the /api/posture document.
type Payload struct {
	Root string   `json:"root"`
	Rows []Record `json:"rows"`
}

// Record is one host, benchmark, and quarter.
type Record struct {
	ID             string   `json:"id"`
	Host           string   `json:"host"`
	Quarter        string   `json:"quarter"`
	QuarterID      string   `json:"quarter_id"`
	Benchmark      string   `json:"benchmark"`
	BenchmarkLabel string   `json:"benchmark_label"`
	BenchmarkID    string   `json:"benchmark_id"`
	Release        string   `json:"release"`
	OS             string   `json:"os"`
	Handoff        string   `json:"handoff"`
	Open           *int     `json:"open"`
	Cat1           *int     `json:"cat1"`
	NotReviewed    *int     `json:"not_reviewed"`
	NotApplicable  *int     `json:"not_applicable"`
	NotAFinding    *int     `json:"not_a_finding"`
	Changed        *int     `json:"changed"`
	Path           string   `json:"path"`
	Identity       string   `json:"identity"`
	Lines          []string `json:"lines"`
}

type rule struct {
	Group    string
	Severity string
	Status   string
	Comment  string
	Check    string
	Title    string
}

type loaded struct {
	BenchmarkID string
	Benchmark   string
	Release     string
	Size        *int
	Host        string
	FQDN        string
	IP          string
	Role        string
	Note        string
	Rules       []rule
	Path        string
	Quarter     string
}

type slot struct {
	Quarter     string
	Host        string
	BenchmarkID string
	OS          string
	Release     string
}

type key struct {
	Quarter     string
	Host        string
	BenchmarkID string
}

// Collect reads root and returns the posture rows.
func Collect(root string) (Payload, error) {
	root = resolve(root)
	found, err := discover(root)
	if err != nil {
		return Payload{}, err
	}
	watched := expectedRows(root)
	quarters := map[string]struct{}{}
	for item := range found {
		quarters[item.Quarter] = struct{}{}
	}
	for _, row := range watched {
		quarters[row.Quarter] = struct{}{}
	}
	order := make([]string, 0, len(quarters))
	for quarter := range quarters {
		order = append(order, quarter)
	}
	sort.Slice(order, func(i, j int) bool {
		return quarterLess(order[i], order[j])
	})
	var dated []string
	for _, quarter := range order {
		if quarter != "" {
			dated = append(dated, quarter)
		}
	}
	previousOf := map[string]string{}
	for i, quarter := range dated {
		if i > 0 {
			previousOf[quarter] = dated[i-1]
		}
	}
	slots := map[key]slot{}
	for _, row := range watched {
		slots[key{row.Quarter, row.Host, row.BenchmarkID}] = row
	}
	for item, file := range found {
		if _, ok := slots[item]; !ok {
			slots[item] = slot{
				Quarter: item.Quarter, Host: file.Host, BenchmarkID: file.BenchmarkID, Release: file.Release,
			}
		}
	}
	keys := make([]key, 0, len(slots))
	for item := range slots {
		keys = append(keys, item)
	}
	sort.Slice(keys, func(i, j int) bool {
		yi, pi := quarterParts(keys[i].Quarter)
		yj, pj := quarterParts(keys[j].Quarter)
		if yi != yj {
			return yi > yj
		}
		if pi != pj {
			return pi > pj
		}
		if keys[i].Host != keys[j].Host {
			return keys[i].Host < keys[j].Host
		}
		return keys[i].BenchmarkID < keys[j].BenchmarkID
	})
	rows := make([]Record, 0, len(keys))
	for _, item := range keys {
		current := slots[item]
		file := found[item]
		var previous *loaded
		if prior := previousOf[item.Quarter]; prior != "" {
			if earlier, ok := found[key{prior, item.Host, item.BenchmarkID}]; ok {
				clone := *earlier
				clone.Quarter = prior
				previous = &clone
			}
		}
		name := benchmarkNames[item.BenchmarkID]
		if file != nil {
			if name == "" {
				name = file.Benchmark
			}
		} else if name == "" {
			name = item.BenchmarkID
		}
		osName := current.OS
		if osName == "" {
			osName = osFor(item.BenchmarkID, name)
		}
		release := ""
		if file != nil {
			release = file.Release
		}
		if release == "" {
			release = current.Release
		}
		label := name
		if release != "" {
			label = name + " " + release
		}
		id := item.Quarter + "|" + item.Host + "|" + item.BenchmarkID
		if file == nil {
			rows = append(rows, Record{
				ID: id, Host: item.Host, Quarter: quarterLabel(item.Quarter), QuarterID: item.Quarter,
				Benchmark: name, BenchmarkLabel: label, BenchmarkID: item.BenchmarkID, Release: release,
				OS: osName, Handoff: "Missing", Lines: highlights(nil, previous),
			})
			continue
		}
		open, reviewed, applicable, finding, cat1 := counts(file.Rules)
		reason := blockedReason(file)
		handoff := "Ready"
		if reason != "" {
			handoff = "Blocked"
		}
		rows = append(rows, Record{
			ID: id, Host: item.Host, Quarter: quarterLabel(item.Quarter), QuarterID: item.Quarter,
			Benchmark: name, BenchmarkLabel: label, BenchmarkID: item.BenchmarkID, Release: release,
			OS: osName, Handoff: handoff,
			Open: intPtr(open), Cat1: intPtr(cat1), NotReviewed: intPtr(reviewed),
			NotApplicable: intPtr(applicable), NotAFinding: intPtr(finding),
			Changed: changedCount(file, previous),
			Path:    file.Path, Identity: identity(file), Lines: highlights(file, previous),
		})
	}
	return Payload{Root: root, Rows: rows}, nil
}

func intPtr(n int) *int { return &n }

func resolve(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

func discover(root string) (map[key]*loaded, error) {
	found := map[key]*loaded{}
	newest := map[key]int64{}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return found, nil
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			fmt.Printf("sitrep: skipped %s\n", path)
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".cklb") {
			return nil
		}
		file, err := loadCKLB(root, path)
		if err != nil {
			fmt.Printf("sitrep: skipped %s\n", path)
			return nil
		}
		item := key{file.Quarter, file.Host, file.BenchmarkID}
		stat, err := os.Stat(path)
		if err != nil {
			fmt.Printf("sitrep: skipped %s\n", path)
			return nil
		}
		modified := stat.ModTime().UnixNano()
		if previous, ok := newest[item]; ok && modified < previous {
			return nil
		}
		newest[item] = modified
		found[item] = file
		return nil
	})
	return found, err
}

func loadCKLB(root, path string) (*loaded, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Stigs      []json.RawMessage `json:"stigs"`
		TargetData struct {
			HostName string `json:"host_name"`
			FQDN     string `json:"fqdn"`
			IP       string `json:"ip_address"`
			Role     string `json:"role"`
			Comments string `json:"comments"`
		} `json:"target_data"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if len(document.Stigs) == 0 {
		return nil, fmt.Errorf("no stigs")
	}
	var stig struct {
		StigID      string          `json:"stig_id"`
		StigName    string          `json:"stig_name"`
		Version     json.RawMessage `json:"version"`
		StigVersion json.RawMessage `json:"stig_version"`
		ReleaseInfo string          `json:"release_info"`
		Size        *int            `json:"size"`
		Rules       []struct {
			GroupID      string `json:"group_id"`
			Severity     string `json:"severity"`
			Status       string `json:"status"`
			Comments     string `json:"comments"`
			CheckContent string `json:"check_content"`
			RuleTitle    string `json:"rule_title"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(document.Stigs[0], &stig); err != nil {
		return nil, err
	}
	rules := make([]rule, 0, len(stig.Rules))
	for _, item := range stig.Rules {
		rules = append(rules, rule{
			Group: item.GroupID, Severity: strings.ToLower(item.Severity), Status: item.Status,
			Comment: strings.TrimSpace(item.Comments), Check: strings.TrimSpace(item.CheckContent), Title: item.RuleTitle,
		})
	}
	release := releaseFromStig(stig.ReleaseInfo, rawString(stig.Version), rawString(stig.StigVersion))
	if release == "" {
		release = releaseFromSidecar(path)
	}
	name := benchmarkNames[stig.StigID]
	if name == "" {
		name = stig.StigName
		if name == "" {
			name = stig.StigID
		}
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	return &loaded{
		BenchmarkID: stig.StigID, Benchmark: name, Release: release, Size: stig.Size,
		Host: hostFromPath(root, path, document.TargetData.HostName),
		FQDN: document.TargetData.FQDN, IP: document.TargetData.IP, Role: document.TargetData.Role,
		Note: strings.TrimSpace(document.TargetData.Comments), Rules: rules, Path: rel,
		Quarter: quarterFromPath(root, path),
	}, nil
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if dec.Decode(&number) == nil {
		return number.String()
	}
	return ""
}

func expectedRows(root string) []slot {
	raw, err := os.ReadFile(filepath.Join(root, "expected.json"))
	if err != nil {
		return nil
	}
	var document map[string][]struct {
		Host        string `json:"host"`
		BenchmarkID string `json:"benchmark_id"`
		OS          string `json:"os"`
		Release     string `json:"release"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		fmt.Printf("sitrep: skipped %s\n", filepath.Join(root, "expected.json"))
		return nil
	}
	var rows []slot
	for quarter, items := range document {
		for _, item := range items {
			rows = append(rows, slot{
				Quarter: quarter, Host: item.Host, BenchmarkID: item.BenchmarkID,
				OS: item.OS, Release: versionReleaseLabel(item.Release),
			})
		}
	}
	return rows
}

func versionReleaseLabel(text string) string {
	match := versionRelease.FindStringSubmatch(text)
	if match == nil {
		return ""
	}
	return fmt.Sprintf("V%dR%d", atoi(match[1]), atoi(match[2]))
}

func releaseFromStig(info, version, stigVersion string) string {
	if label := versionReleaseLabel(info); label != "" {
		return label
	}
	chosen := strings.TrimSpace(version)
	if chosen == "" {
		chosen = strings.TrimSpace(stigVersion)
	}
	versionMatch := versionNumber.FindStringSubmatch(chosen)
	releaseMatch := releaseNumber.FindStringSubmatch(info)
	if versionMatch != nil && releaseMatch != nil {
		return fmt.Sprintf("V%dR%d", atoi(versionMatch[1]), atoi(releaseMatch[1]))
	}
	return ""
}

func releaseFromSidecar(path string) string {
	raw, err := os.ReadFile(path + ".provenance.json")
	if err != nil {
		return ""
	}
	var document struct {
		Benchmark struct {
			Path string `json:"path"`
		} `json:"benchmark"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return ""
	}
	return versionReleaseLabel(document.Benchmark.Path)
}

func atoi(text string) int {
	n := 0
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func quarterFromPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	parts := strings.Split(rel, string(filepath.Separator))
	found := ""
	if len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	for _, part := range parts {
		for _, pattern := range quarterDirs {
			match := pattern.FindStringSubmatch(part)
			if match == nil {
				continue
			}
			year := matchGroup(pattern, match, "year")
			piece := matchGroup(pattern, match, "part")
			found = fmt.Sprintf("%d-q%d", atoi(year), atoi(piece))
		}
	}
	return found
}

func matchGroup(pattern *regexp.Regexp, match []string, name string) string {
	for i, label := range pattern.SubexpNames() {
		if label == name {
			return match[i]
		}
	}
	return ""
}

func hostFromPath(root, path, target string) string {
	host := strings.TrimSpace(target)
	if host != "" {
		return host
	}
	parent := filepath.Base(filepath.Dir(path))
	if parent != "" && parent != filepath.Base(root) && !strings.HasSuffix(parent, "_STIG") && !isQuarter(parent) {
		return parent
	}
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

func isQuarter(part string) bool {
	for _, pattern := range quarterDirs {
		if pattern.MatchString(part) {
			return true
		}
	}
	return false
}

func osFor(benchmarkID, fallback string) string {
	if match := rhelOS.FindStringSubmatch(benchmarkID); match != nil {
		return "RHEL " + match[1]
	}
	switch {
	case strings.Contains(benchmarkID, "IOS-XE") || strings.Contains(benchmarkID, "IOS_XE"):
		return "IOS-XE"
	case strings.Contains(benchmarkID, "IOS-XR") || strings.Contains(benchmarkID, "IOS_XR"):
		return "IOS-XR"
	case strings.Contains(benchmarkID, "NX-OS") || strings.Contains(benchmarkID, "NX_OS"):
		return "NX-OS"
	case strings.HasPrefix(benchmarkID, "Cisco_IOS"):
		return "IOS"
	case strings.HasPrefix(benchmarkID, "Cisco_ASA"):
		return "ASA"
	default:
		return fallback
	}
}

func counts(rules []rule) (open, reviewed, applicable, finding, cat1 int) {
	for _, item := range rules {
		switch item.Status {
		case "open":
			open++
			if item.Severity == "high" {
				cat1++
			}
		case "not_reviewed":
			reviewed++
		case "not_applicable":
			applicable++
		case "not_a_finding":
			finding++
		}
	}
	return open, reviewed, applicable, finding, cat1
}

func blockedReason(file *loaded) string {
	if file.Size != nil && *file.Size != len(file.Rules) {
		return "Rule count does not match the checklist size."
	}
	for _, item := range file.Rules {
		if item.Check == "" {
			return "Check text is empty on at least one rule."
		}
	}
	note := strings.ToLower(file.Note)
	if strings.Contains(note, "no closing end") || strings.Contains(note, "incomplete") {
		return file.Note
	}
	if file.IP == "" {
		return "Target page has no IP."
	}
	return ""
}

func highlights(current, previous *loaded) []string {
	var lines []string
	if current == nil {
		if previous == nil {
			return []string{"No checklist in this tree."}
		}
		return []string{fmt.Sprintf("Checklist was present in %s and is absent from this quarter.", quarterLabel(previous.Quarter))}
	}
	if reason := blockedReason(current); reason != "" {
		lines = append(lines, "Blocked: "+reason)
	}
	if previous != nil {
		prior := map[string]rule{}
		for _, item := range previous.Rules {
			prior[item.Group] = item
		}
		shown := 0
		for _, item := range current.Rules {
			old, ok := prior[item.Group]
			if !ok || old.Status == item.Status {
				continue
			}
			if shown == 6 {
				break
			}
			lines = append(lines, fmt.Sprintf("Changed: %s moved from %s to %s. %s", item.Group, words(old.Status), words(item.Status), item.Comment))
			shown++
		}
	}
	catShown := 0
	for _, item := range current.Rules {
		if item.Status != "open" || item.Severity != "high" {
			continue
		}
		if catShown == 4 {
			break
		}
		lines = append(lines, fmt.Sprintf("CAT I open: %s. %s", item.Group, item.Comment))
		catShown++
	}
	factShown := 0
	for _, item := range current.Rules {
		if item.Status != "not_reviewed" {
			continue
		}
		lower := strings.ToLower(item.Comment)
		match := false
		for _, word := range siteFact {
			if strings.Contains(lower, word) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		if factShown == 3 {
			break
		}
		lines = append(lines, fmt.Sprintf("Needs a site fact: %s. %s", item.Group, item.Comment))
		factShown++
	}
	if len(lines) == 0 {
		return []string{"No status changes, CAT I opens, or site facts on this checklist."}
	}
	return lines
}

func words(status string) string {
	switch status {
	case "open":
		return "Open"
	case "not_a_finding":
		return "Not a finding"
	case "not_reviewed":
		return "Not reviewed"
	case "not_applicable":
		return "Not applicable"
	default:
		return status
	}
}

func changedCount(current, previous *loaded) *int {
	if current == nil || previous == nil {
		return nil
	}
	prior := map[string]string{}
	for _, item := range previous.Rules {
		prior[item.Group] = item.Status
	}
	n := 0
	for _, item := range current.Rules {
		old, ok := prior[item.Group]
		if !ok {
			old = item.Status
		}
		if old != item.Status {
			n++
		}
	}
	return &n
}

func identity(file *loaded) string {
	var parts []string
	for _, part := range []string{file.FQDN, file.IP, file.Role} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " · ")
}

func quarterLabel(quarter string) string {
	if quarter == "" {
		return "Undated"
	}
	year, part, ok := strings.Cut(quarter, "-q")
	if !ok {
		return "Undated"
	}
	return year + " Q" + part
}

func quarterParts(quarter string) (int, int) {
	if quarter == "" || !strings.Contains(quarter, "-q") {
		return 0, 0
	}
	year, part, _ := strings.Cut(quarter, "-q")
	return atoi(year), atoi(part)
}

func quarterLess(left, right string) bool {
	ly, lp := quarterParts(left)
	ry, rp := quarterParts(right)
	if ly != ry {
		return ly < ry
	}
	return lp < rp
}
