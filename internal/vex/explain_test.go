package vex

import (
	"testing"

	"github.com/corefense-security/kcond"
)

func TestExplain(t *testing.T) {
	cfg := kcond.Config{"CONFIG_IP_SCTP": 'm', "CONFIG_NET": 'y', "CONFIG_KVM": 'm', "CONFIG_KVM_X86": 'm'}
	for _, tc := range []struct {
		gate string
		want kcond.Tri
		why  string
	}{
		{"true", kcond.True, "no config gate: always compiled"},
		{"CONFIG_NET", kcond.True, "CONFIG_NET=y"},
		{"CONFIG_DLM", kcond.False, "CONFIG_DLM=n"},
		// Every && operand holds: each with its value.
		{"CONFIG_IP_SCTP && CONFIG_NET", kcond.True, "CONFIG_IP_SCTP=m && CONFIG_NET=y"},
		// One failing && operand decides alone.
		{"CONFIG_DLM && CONFIG_NET", kcond.False, "CONFIG_DLM=n"},
		// The || branch that holds, not the one that doesn't.
		{"CONFIG_DLM || (CONFIG_IP_SCTP && CONFIG_NET)", kcond.True, "CONFIG_IP_SCTP=m && CONFIG_NET=y"},
		// No || branch holds: each branch by the operand that failed it.
		{"CONFIG_DLM || (CONFIG_IP_SCTP && CONFIG_USB)", kcond.False, "CONFIG_DLM=n || CONFIG_USB=n"},
		// =y and =m tests name the value they needed.
		{"CONFIG_KVM=y", kcond.False, "CONFIG_KVM=m (needs y)"},
		// An unset option fails both tests the same way: one reason.
		{"CONFIG_DLM=y || CONFIG_DLM=m", kcond.False, "CONFIG_DLM=n"},
		{"CONFIG_KVM && (CONFIG_KVM=y || CONFIG_KVM_X86=m) && CONFIG_KVM_X86", kcond.True,
			"CONFIG_KVM=m && CONFIG_KVM_X86=m"},
		{"!CONFIG_NET", kcond.False, "CONFIG_NET=y (must be off)"},
		{"!CONFIG_DLM && CONFIG_NET", kcond.True, "CONFIG_DLM=n && CONFIG_NET=y"},
	} {
		e, err := kcond.Parse(tc.gate)
		if err != nil {
			t.Fatalf("%s: %v", tc.gate, err)
		}
		got, why, _ := explain(e, cfg)
		if got != tc.want || why != tc.why {
			t.Errorf("%s:\n got %v %q\nwant %v %q", tc.gate, got, why, tc.want, tc.why)
		}
		if got != e.Eval(cfg) {
			t.Errorf("%s: explain %v, Eval %v", tc.gate, got, e.Eval(cfg))
		}
	}
}
