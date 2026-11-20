package posture

import (
	"testing"

	"github.com/zcook44/sitrep/internal/demo"
)

func TestDemoTree(t *testing.T) {
	dir := t.TempDir()
	if err := demo.Write(dir); err != nil {
		t.Fatal(err)
	}
	body, err := Collect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Rows) != 20 {
		t.Fatalf("rows = %d, want 20", len(body.Rows))
	}
	var missing, blocked, ready int
	labels := map[string]int{}
	for _, row := range body.Rows {
		labels[row.BenchmarkLabel]++
		switch row.Handoff {
		case "Missing":
			missing++
			if row.Host != "nx-access-01" || row.QuarterID != "2026-q4" || row.Release != "V3R4" {
				t.Fatalf("unexpected missing row %+v", row)
			}
		case "Blocked":
			blocked++
		case "Ready":
			ready++
		default:
			t.Fatalf("handoff %s", row.Handoff)
		}
	}
	if missing != 1 || blocked != 2 || ready != 17 {
		t.Fatalf("missing %d blocked %d ready %d", missing, blocked, ready)
	}
	if labels["RHEL 9 V2R5"] != 6 || labels["IOS-XE L2S V3R2"] != 2 {
		t.Fatalf("labels %#v", labels)
	}
}
