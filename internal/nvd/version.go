package nvd

import (
	"strconv"
	"strings"
	"unicode"
)

// preRelease suffixes sort before the release they lead up to (1.0rc1 < 1.0). The single letters
// "a" and "b" only do with a number straight after them: 1.0a1 is an alpha, but 1.1.1a is a patch
// level of 1.1.1.
var preRelease = map[string]bool{"alpha": true, "beta": true, "pre": true, "rc": true, "dev": true}

// Compare orders two package versions: -1, 0 or 1. It splits each version into runs of digits
// and letters and compares run by run, numbers numerically. A trailing letter run is a patch
// level (10.3p1 > 10.3) unless it names a pre-release (1.0rc1 < 1.0). A missing number counts as
// zero, so 2.0 equals 2.0.0. Build metadata after "+" (Yocto's "+git…") and an epoch ("1:") are
// ignored.
func Compare(a, b string) int {
	ta, tb := tokens(clean(a)), tokens(clean(b))
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			if tb[i].isZero() {
				continue
			}
			return -tailSign(tb[i])
		case i >= len(tb):
			if ta[i].isZero() {
				continue
			}
			return tailSign(ta[i])
		}
		if c := cmpToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	return 0
}

func clean(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.Index(v, ":"); i >= 0 && isDigits(v[:i]) {
		v = v[i+1:]
	}
	if i := strings.Index(v, "+"); i > 0 {
		v = v[:i]
	}
	return strings.TrimPrefix(v, "v")
}

type token struct {
	num   int
	text  string
	isNum bool
	pre   bool // text naming a pre-release
}

func (t token) isZero() bool { return t.isNum && t.num == 0 }

func tokens(v string) []token {
	var out []token
	var cur strings.Builder
	curNum := false
	flush := func(beforeDigit bool) {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		if curNum {
			n, _ := strconv.Atoi(strings.TrimLeft(s, "0"))
			out = append(out, token{num: n, isNum: true})
		} else {
			out = append(out, token{text: s, pre: preRelease[s] || (beforeDigit && (s == "a" || s == "b"))})
		}
		cur.Reset()
	}
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			if !curNum {
				flush(true)
			}
			curNum = true
			cur.WriteRune(r)
		case unicode.IsLetter(r):
			if curNum {
				flush(false)
			}
			curNum = false
			cur.WriteRune(r)
		default: // separators: . - _ ~
			flush(false)
		}
	}
	flush(false)
	return out
}

// tailSign is the sign an extra trailing token gives the longer version.
func tailSign(t token) int {
	if t.pre {
		return -1
	}
	return 1
}

func cmpToken(a, b token) int {
	switch {
	case a.isNum && b.isNum:
		return cmpInt(a.num, b.num)
	case a.isNum: // 1.0.1 > 1.0rc1, 1.1 > 1.p
		return 1
	case b.isNum:
		return -cmpToken(b, a)
	}
	if a.pre != b.pre {
		if a.pre {
			return -1
		}
		return 1
	}
	return strings.Compare(a.text, b.text)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
