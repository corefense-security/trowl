package vex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/corefense-security/trowl/internal/sbom"
)

// allCompiled is an Evaluator that finds every file compiled.
type allCompiled struct{ calls int }

func (c *allCompiled) Assess(files []string) *sbom.Assessment {
	c.calls++
	return &sbom.Assessment{Status: Affected}
}

func loadCDX(t *testing.T, vulns string) *sbom.Sbom {
	t.Helper()
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","version":1,
"components":[{"bom-ref":"linux","name":"linux","version":"6.18.52","cpe":"cpe:2.3:o:linux:linux_kernel:6.18.52:*:*:*:*:*:*:*"}],
"vulnerabilities":[` + vulns + `]}`
	p := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(p, []byte(bom), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := sbom.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func applyAll(sb *sbom.Sbom, cves ...string) {
	files, in := map[string][]string{}, map[[2]string]bool{}
	for _, comp := range sb.KernelComponents() {
		for _, cve := range cves {
			files[cve] = []string{"net/x.c"}
			in[[2]string{comp, cve}] = true
		}
	}
	Apply(sb, &allCompiled{}, files, in)
}

// A CycloneDX code_not_present makes the same config claim as Yocto's not-applicable-config, so
// the kernel tree check covers it. Other justifications are left alone.
func TestCycloneDXCodeNotPresentIsChecked(t *testing.T) {
	sb := loadCDX(t, `
 {"id":"CVE-1","analysis":{"state":"not_affected","justification":"code_not_present"},"affects":[{"ref":"linux"}]},
 {"id":"CVE-2","analysis":{"state":"not_affected","justification":"requires_configuration"},"affects":[{"ref":"linux"}]},
 {"id":"CVE-3","analysis":{"state":"exploitable"},"affects":[{"ref":"linux"}]}`)
	applyAll(sb, "CVE-1", "CVE-2", "CVE-3")
	comp := sb.KernelComponents()[0]

	a := sb.AssessmentOf("CVE-1", comp)
	if a == nil || a.Status != Affected || !a.Defies {
		t.Errorf("code_not_present: got %+v, want a checked, disagreeing Affected", a)
	}
	if sb.AssessmentOf("CVE-2", comp) != nil || sb.Vex("CVE-2", comp) != "not_affected" {
		t.Error("requires_configuration: the SBOM's not_affected should be kept unchecked")
	}
}

// A VEX file that restates the CVE with another justification drops the code_not_present claim.
func TestLaterJustificationReplacesCodeNotPresent(t *testing.T) {
	sb := loadCDX(t, `
 {"id":"CVE-1","analysis":{"state":"not_affected","justification":"code_not_present"},"affects":[{"ref":"linux"}]}`)
	vex := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"vulnerabilities":[
 {"id":"CVE-1","analysis":{"state":"not_affected","justification":"protected_by_mitigating_control"},
  "affects":[{"ref":"urn:cdx:1/1#linux"}]}]}`
	p := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(p, []byte(vex), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sbom.LoadVEX(sb, p); err != nil {
		t.Fatal(err)
	}
	comp := sb.KernelComponents()[0]
	if sb.ConfigExcluded("CVE-1", comp) {
		t.Error("the VEX file's justification should replace code_not_present")
	}
}
