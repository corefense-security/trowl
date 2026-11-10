package vex

import (
	"strings"

	"github.com/corefense-security/kcond"
)

// explain evaluates a gate against the config as kcond's Eval does and says why, in the gate's own
// shape: each option it names with the value the config gives it, joined by the gate's && and ||.
// An && that one failing option decides, or an || that one holding branch decides, is explained by
// that operand alone, so a compiled file shows the branch that compiled it and a file left out the
// option that left it out:
//
//	CONFIG_DLM || (CONFIG_IP_SCTP && CONFIG_NET), DLM unset, IP_SCTP=m, NET=y
//	  → true,  "CONFIG_IP_SCTP=m && CONFIG_NET=y"
//	the same with NET unset
//	  → false, "CONFIG_DLM=n || CONFIG_NET=n"
//
// The third result tells the caller that the reason joins operands, so it goes in parentheses.
func explain(e *kcond.Expr, cfg kcond.Config) (kcond.Tri, string, bool) {
	switch e.Op {
	case kcond.OpConst:
		if e.Val {
			return kcond.True, "no config gate: always compiled", false
		}
		return kcond.False, "never compiled in this build", false
	case kcond.OpVar:
		t, why := leaf(e, cfg, false)
		return t, why, false
	case kcond.OpNot:
		if a := e.Args[0]; a.Op == kcond.OpVar {
			t, why := leaf(a, cfg, true)
			return t, why, false
		}
		t, why, _ := explain(e.Args[0], cfg)
		return not(t), "not (" + why + ")", false
	}
	short, res, sep := kcond.False, kcond.True, " && "
	if e.Op == kcond.OpOr {
		short, res, sep = kcond.True, kcond.False, " || "
	}
	parts := make([]string, 0, len(e.Args))
	seen := map[string]bool{} // an operand an || branch explains may also be one of its own
	for _, a := range e.Args {
		t, why, joined := explain(a, cfg)
		if t == short {
			return t, why, joined
		}
		if t == kcond.Unknown {
			res = kcond.Unknown
		}
		if joined {
			why = "(" + why + ")"
		}
		if !seen[why] {
			seen[why] = true
			parts = append(parts, why)
		}
	}
	return res, strings.Join(parts, sep), len(parts) > 1
}

// leaf evaluates one option test, or its negation, and writes the value the config gives the
// option, adding what the gate needed when that is not the value: CONFIG_NET=y,
// CONFIG_KVM=m (needs y), CONFIG_X=y (must be off).
func leaf(v *kcond.Expr, cfg kcond.Config, negated bool) (kcond.Tri, string) {
	if !kcond.IsSymbol(v.Name) {
		return kcond.Unknown, v.Name + " (not a config option)"
	}
	t := v.Eval(cfg)
	if negated {
		t = not(t)
	}
	val := "n"
	if c, ok := cfg[v.Name]; ok {
		val = string(c)
	}
	why := v.Name + "=" + val
	if t == kcond.True {
		return t, why
	}
	switch {
	case negated && v.State == kcond.Enabled:
		why += " (must be off)"
	case negated:
		why += " (must not be " + wanted(v.State) + ")"
	case v.State != kcond.Enabled && val != "n":
		// Only a value of the wrong kind needs saying: an unset option fails
		// =y and =m alike, and X=y || X=m then reads as one CONFIG_X=n.
		why += " (needs " + wanted(v.State) + ")"
	}
	return t, why
}

func wanted(s kcond.State) string {
	if s == kcond.Module {
		return "m"
	}
	return "y"
}

func not(t kcond.Tri) kcond.Tri {
	switch t {
	case kcond.True:
		return kcond.False
	case kcond.False:
		return kcond.True
	}
	return kcond.Unknown
}
