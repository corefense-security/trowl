package nvd

import (
	"strconv"
	"strings"
	"unicode"
)

// preRelease suffixes sort before the release they lead up to (1.0rc1 < 1.0).
var preRelease = map[string]bool{"alpha": true, "a": true, "beta": true, "b": true, "pre": true,
	"rc": true, "dev": true}

// Compare orders two package versions: -1, 0 or 1. It splits each version into runs of digits
// and letters and compares run by run, numbers numerically. A trailing letter run is a patch
// level (10.3p1 > 10.3) unless it names a pre-release (1.0rc1 < 1.0). Build metadata after "+"
// (Yocto's "+git…") and an epoch ("1:") are ignored.
func Compare(a, b string) int {
	ta, tb := tokens(clean(a)), tokens(clean(b))
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			return -tailSign(tb[i])
		case i >= len(tb):
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
}

func tokens(v string) []token {
	var out []token
	var cur strings.Builder
	curNum := false
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		if curNum {
			n, _ := strconv.Atoi(strings.TrimLeft(s, "0"))
			out = append(out, token{num: n, isNum: true})
		} else {
			out = append(out, token{text: s})
		}
		cur.Reset()
	}
	for _, r := range v {
		switch {
		case unicode.IsDigit(r):
			if !curNum {
				flush()
			}
			curNum = true
			cur.WriteRune(r)
		case unicode.IsLetter(r):
			if curNum {
				flush()
			}
			curNum = false
			cur.WriteRune(r)
		default: // separators: . - _ ~
			flush()
		}
	}
	flush()
	return out
}

// tailSign is the sign an extra trailing token gives the longer version.
func tailSign(t token) int {
	if !t.isNum && preRelease[t.text] {
		return -1
	}
	return 1
}

func cmpToken(a, b token) int {
	switch {
	case a.isNum && b.isNum:
		return cmpInt(a.num, b.num)
	case a.isNum: // 1.0.1 > 1.0rc1, 1.1 > 1.p
		if preRelease[b.text] {
			return 1
		}
		return 1
	case b.isNum:
		return -cmpToken(b, a)
	}
	pa, pb := preRelease[a.text], preRelease[b.text]
	if pa != pb {
		if pa {
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
