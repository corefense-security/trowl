package vex

import (
	"testing"

	"github.com/corefense-security/kcond"
	"github.com/corefense-security/kcond/gate"
)

func TestPlace(t *testing.T) {
	k := &Kernel{
		config: kcond.Config{"CONFIG_IP_SCTP": 'm', "CONFIG_IPV6": 'm', "CONFIG_FOO": 'm', "CONFIG_BAR": 'y',
			"CONFIG_A": 'y', "CONFIG_B": 'y'},
		modules: &Modules{Dir: "/lib/modules/6.18.52", objects: map[string]bool{"drivers/d/foo": true}},
	}
	sctp := gate.Link{Object: "net/sctp/sctp", Builtin: "CONFIG_IP_SCTP=y", Module: "CONFIG_IP_SCTP=m"}
	foo := gate.Link{Object: "drivers/d/foo", Builtin: "CONFIG_A=y && CONFIG_FOO=y", Module: "CONFIG_A && CONFIG_FOO=m"}
	bar := gate.Link{Object: "drivers/d/bar", Builtin: "CONFIG_B=y && CONFIG_BAR=y", Module: "CONFIG_B && CONFIG_BAR=m"}
	for _, tc := range []struct {
		name    string
		links   []gate.Link
		modules bool // the image's modules were read
		want    judgement
	}{
		{"a module the image lacks", []gate.Link{sctp}, true, judgement{verdict: notShipped,
			reason: "sctp.ko not in image", config: "CONFIG_IP_SCTP=m",
			module: "/lib/modules/6.18.52/kernel/net/sctp/sctp.ko"}},
		{"a module the image ships", []gate.Link{foo}, true, judgement{verdict: compiled,
			reason: "foo.ko in image", config: "CONFIG_A=y && CONFIG_FOO=m",
			module: "/lib/modules/6.18.52/kernel/drivers/d/foo.ko"}},
		// The first link held as a module, the second built in: the code is in vmlinux.
		{"built in one way, a module another", []gate.Link{sctp, bar}, true, judgement{verdict: compiled,
			reason: "built into vmlinux", config: "CONFIG_B=y && CONFIG_BAR=y"}},
		// net/ipv6/mcast_snoop.c: its gate tests CONFIG_IPV6, =m here, but obj-y links it in.
		{"built in under a module's option", []gate.Link{{Object: "net/ipv6/mcast_snoop", Builtin: "CONFIG_IPV6", Module: "false"}},
			true, judgement{verdict: compiled, reason: "built into vmlinux", config: "CONFIG_IPV6=m"}},
		// Without the image's modules, nothing says the module is missing.
		{"modules not read", []gate.Link{sctp}, false, judgement{verdict: compiled,
			reason: "sctp.ko, counted as shipped: the image's modules weren't found", config: "CONFIG_IP_SCTP=m"}},
		{"no links", nil, true, judgement{verdict: compiled, reason: "the gate's reason"}},
		// Compiled, but neither linked nor a module, as an extra-y object.
		{"neither", []gate.Link{{Object: "arch/x86/kernel/head_64", Builtin: "false", Module: "false"}}, true,
			judgement{verdict: compiled, reason: "the gate's reason"}},
		{"undecidable", []gate.Link{{Object: "x/y", Builtin: "\"$(if $(X))\"", Module: "false"}}, true,
			judgement{verdict: compiled, reason: "the gate's reason; whether it is built in depends on more than the config"}},
	} {
		kk := *k
		if !tc.modules {
			kk.modules = nil
		}
		if got := kk.place(tc.links, "the gate's reason"); got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

// TestAssessNotShipped checks the status a file in a missing module gives the CVE.
func TestAssessNotShipped(t *testing.T) {
	for _, tc := range []struct {
		verdicts                    []string
		status, justification, note string
	}{
		{[]string{notShipped}, NotAffected, componentNotPresent, "only in a missing module"},
		{[]string{notShipped, notCompiled}, NotAffected, componentNotPresent, "one file in a missing module, one not compiled"},
		{[]string{notShipped, compiled}, Affected, "", "another file compiled into the image"},
		{[]string{notShipped, unknown}, UnderInvestigation, "", "another file undecided"},
	} {
		counts := map[string]int{}
		for _, v := range tc.verdicts {
			counts[v]++
		}
		if s, j, _ := decide(counts); s != tc.status || j != tc.justification {
			t.Errorf("%s: got %s %s, want %s %s", tc.note, s, j, tc.status, tc.justification)
		}
	}
}
