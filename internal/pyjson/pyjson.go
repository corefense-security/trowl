// Package pyjson writes JSON byte-for-byte like Python's json.dumps, and keeps object keys in
// insertion order. The report and the model's cache keys were defined by the Python version of
// trowl, so the output format is kept identical.
package pyjson

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Obj is an insertion-ordered JSON object, like a Python dict.
type Obj struct {
	keys []string
	vals map[string]any
}

func New() *Obj { return &Obj{vals: map[string]any{}} }

// O builds an object from alternating key, value arguments.
func O(kv ...any) *Obj {
	o := New()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

// Set adds or replaces a key; a replaced key keeps its original position, as in Python.
func (o *Obj) Set(k string, v any) *Obj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *Obj) Get(k string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[k]
	return v, ok
}

// G returns the value or nil.
func (o *Obj) G(k string) any {
	v, _ := o.Get(k)
	return v
}

func (o *Obj) Keys() []string {
	if o == nil {
		return nil
	}
	return o.keys
}

func (o *Obj) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Copy is a shallow copy, like dict(o).
func (o *Obj) Copy() *Obj {
	c := New()
	for _, k := range o.Keys() {
		c.Set(k, o.vals[k])
	}
	return c
}

// Counter counts keys in first-seen order, like dict(collections.Counter(...)).
type Counter struct{ o *Obj }

func NewCounter() *Counter { return &Counter{New()} }

func (c *Counter) Add(k string, n int) {
	v, _ := c.o.Get(k)
	cur, _ := v.(int)
	c.o.Set(k, cur+n)
}

func (c *Counter) Obj() *Obj      { return c.o }
func (c *Counter) Keys() []string { return c.o.keys }
func (c *Counter) Get(k string) int {
	v, _ := c.o.Get(k)
	n, _ := v.(int)
	return n
}

// MostCommon orders keys by count, highest first; ties keep first-seen order (Python's sort is stable).
func (c *Counter) MostCommon() []string {
	keys := append([]string(nil), c.o.keys...)
	sort.SliceStable(keys, func(i, j int) bool { return c.Get(keys[i]) > c.Get(keys[j]) })
	return keys
}

// Dumps mirrors json.dumps(v, indent=indent) (indent < 0 means no indent) with the given
// item and key separators. Python defaults: (", ", ": ") without indent, ("," , ": ") with it.
func Dumps(v any, indent int, itemSep, keySep string) string {
	var b bytes.Buffer
	enc(&b, v, indent, 0, itemSep, keySep)
	return b.String()
}

// Indent1 is json.dumps(v, indent=1).
func Indent1(v any) string { return Dumps(v, 1, ",", ": ") }

// Compact is json.dumps(v, separators=(",", ":")).
func Compact(v any) string { return Dumps(v, -1, ",", ":") }

// Default is json.dumps(v).
func Default(v any) string { return Dumps(v, -1, ", ", ": ") }

func newline(b *bytes.Buffer, indent, level int) {
	if indent < 0 {
		return
	}
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", indent*level))
}

func enc(b *bytes.Buffer, v any, indent, level int, itemSep, keySep string) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case float64:
		b.WriteString(Float(x))
	case *Obj:
		if x == nil {
			b.WriteString("null")
			return
		}
		if len(x.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(itemSep)
			}
			newline(b, indent, level+1)
			writeString(b, k)
			b.WriteString(keySep)
			enc(b, x.vals[k], indent, level+1, itemSep, keySep)
		}
		newline(b, indent, level)
		b.WriteByte('}')
	case *Counter:
		enc(b, x.o, indent, level, itemSep, keySep)
	case []any:
		encList(b, len(x), func(i int) any { return x[i] }, indent, level, itemSep, keySep)
	case []string:
		encList(b, len(x), func(i int) any { return x[i] }, indent, level, itemSep, keySep)
	case []*Obj:
		encList(b, len(x), func(i int) any { return x[i] }, indent, level, itemSep, keySep)
	default:
		panic(fmt.Sprintf("pyjson: unsupported type %T", v))
	}
}

func encList(b *bytes.Buffer, n int, at func(int) any, indent, level int, itemSep, keySep string) {
	if n == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(itemSep)
		}
		newline(b, indent, level+1)
		enc(b, at(i), indent, level+1, itemSep, keySep)
	}
	newline(b, indent, level)
	b.WriteByte(']')
}

// writeString is json's ensure_ascii encoding: ASCII stays, everything else becomes \uXXXX.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case r < 0x7f || r == 0x7f:
				b.WriteRune(r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

// Float formats like Python's float.__repr__: shortest round-trip digits, fixed notation for
// exponents in [-4, 16), always with a fractional part.
func Float(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.dddde±XX
	mant, expS, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	sign := ""
	if neg {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := fmt.Sprintf("%02d", abs(exp))
		if exp < 0 {
			return sign + m + "e-" + es
		}
		return sign + m + "e+" + es
	}
	if exp >= 0 {
		if len(digits) <= exp+1 {
			return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		}
		return sign + digits[:exp+1] + "." + digits[exp+1:]
	}
	return sign + "0." + strings.Repeat("0", -exp-1) + digits
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
