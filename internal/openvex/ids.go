package openvex

import (
	"net/url"
	"strings"
)

// PURL is the part of a package URL that names a package. Qualifiers and the subpath are left
// out, since tools add different ones for the same package.
type PURL struct{ Type, Namespace, Name, Version string }

// ParsePURL reads "pkg:type/namespace/name@version?qualifiers#subpath". Each part is
// percent-decoded, so "6.18.52%2Bgit" and "6.18.52+git" read the same.
func ParsePURL(s string) (PURL, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return PURL{}, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	rest = strings.Trim(rest, "/")
	var p PURL
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		p.Version, rest = unescape(rest[i+1:]), rest[:i]
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return PURL{}, false
	}
	p.Type = strings.ToLower(parts[0])
	p.Name = unescape(parts[len(parts)-1])
	ns := make([]string, 0, len(parts)-2)
	for _, x := range parts[1 : len(parts)-1] {
		ns = append(ns, unescape(x))
	}
	p.Namespace = strings.Join(ns, "/")
	if p.Name == "" {
		return PURL{}, false
	}
	return p, true
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// Same reports whether p and o name the same package. Names compare without case. A side with no
// version matches any version.
func (p PURL) Same(o PURL) bool {
	return p.Type == o.Type && strings.EqualFold(p.Namespace, o.Namespace) && strings.EqualFold(p.Name, o.Name) &&
		(p.Version == "" || o.Version == "" || p.Version == o.Version)
}

// CPE is the vendor, product and version of a CPE 2.3 or 2.2 name.
type CPE struct{ Vendor, Product, Version string }

// ParseCPE reads "cpe:2.3:a:vendor:product:version:..." or "cpe:/a:vendor:product:version".
func ParseCPE(s string) (CPE, bool) {
	s = strings.TrimSpace(s)
	var f []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		f = splitCPE(s[len("cpe:2.3:"):])
	case strings.HasPrefix(s, "cpe:/"):
		f = strings.Split(s[len("cpe:/"):], ":")
	default:
		return CPE{}, false
	}
	if len(f) < 3 {
		return CPE{}, false
	}
	c := CPE{Vendor: strings.ToLower(f[1]), Product: strings.ToLower(f[2])}
	if len(f) > 3 {
		c.Version = f[3]
	}
	if c.Product == "" || c.Product == "*" {
		return CPE{}, false
	}
	return c, true
}

// splitCPE splits on colons that aren't escaped with a backslash, and drops the escapes.
func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case s[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}

func wildcard(v string) bool { return v == "" || v == "*" || v == "-" }

// Same reports whether c and o name the same product and version. A vendor or version of "*" or
// "-" on either side matches anything.
func (c CPE) Same(o CPE) bool {
	return c.Product == o.Product && (wildcard(c.Vendor) || wildcard(o.Vendor) || c.Vendor == o.Vendor) &&
		(wildcard(c.Version) || wildcard(o.Version) || c.Version == o.Version)
}

// NameVersion reads the package name and version from a PURL, from a CPE's product, or from a
// plain "name@version" or "name".
func NameVersion(s string) (name, version string, ok bool) {
	if p, ok := ParsePURL(s); ok {
		return p.Name, p.Version, true
	}
	if c, ok := ParseCPE(s); ok {
		v := c.Version
		if wildcard(v) {
			v = ""
		}
		return c.Product, v, true
	}
	if strings.Contains(s, ":") || strings.Contains(s, "/") || strings.TrimSpace(s) == "" {
		return "", "", false
	}
	name, version, _ = strings.Cut(strings.TrimSpace(s), "@")
	return name, version, name != ""
}
