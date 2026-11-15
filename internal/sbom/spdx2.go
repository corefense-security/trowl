package sbom

// SPDX 2.2 JSON, as written by Yocto's create-spdx-2.2 (the default up to scarthgap).
//
// Yocto splits one image's SBOM into many documents and ships them as IMAGE.spdx.tar.zst.
// The image document points to the package documents. Each package document has the package and
// its files. Each recipe-* document has the recipe, its CPEs and the CVEs its patches fix. Each
// runtime-* document has a package's runtime dependencies. A reference to another document looks
// like "DocumentRef-x:SPDXRef-y", and the document's externalDocumentRefs say what x is.
//
// SPDX 2.2 has no VEX. The only CVE status in it is the recipe's "CVEs fixed" list.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/corefense-security/trowl/internal/py"
)

const (
	spdx22Version = "SPDX-2.2" // as the documents spell it
	spdx22Format  = "SPDX 2.2" // as the report shows it
)

type spdx2Doc struct {
	SpdxVersion string `json:"spdxVersion"`
	Name        string `json:"name"`
	Namespace   string `json:"documentNamespace"`
	ExtRefs     []struct {
		ID  string `json:"externalDocumentId"`
		Doc string `json:"spdxDocument"`
	} `json:"externalDocumentRefs"`
	Packages []struct {
		ID         string   `json:"SPDXID"`
		Name       string   `json:"name"`
		Version    string   `json:"versionInfo"`
		SourceInfo string   `json:"sourceInfo"`
		HasFiles   []string `json:"hasFiles"`
		ExtRefs    []struct {
			Type    string `json:"referenceType"`
			Locator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Files []struct {
		ID        string `json:"SPDXID"`
		Name      string `json:"fileName"`
		Checksums []struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"checksumValue"`
		} `json:"checksums"`
	} `json:"files"`
	Relationships []struct {
		From string `json:"spdxElementId"`
		Type string `json:"relationshipType"`
		To   string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

// refs maps the document's DocumentRef names to the namespaces they point to.
func (d *spdx2Doc) refs() map[string]string {
	m := map[string]string{}
	for _, r := range d.ExtRefs {
		m[r.ID] = r.Doc
	}
	return m
}

// global makes an element id unique across documents by prefixing its document's namespace.
func (d *spdx2Doc) global(ref string, refs map[string]string) string {
	if docRef, id, ok := strings.Cut(ref, ":"); ok && strings.HasPrefix(docRef, "DocumentRef-") {
		if ns, ok := refs[docRef]; ok {
			return ns + "#" + id
		}
		return ref // points to a document we don't have
	}
	return d.namespace() + "#" + ref
}

func (d *spdx2Doc) namespace() string {
	if d.Namespace != "" {
		return d.Namespace
	}
	return d.Name
}

// spdx2Role reads the role from Yocto's SPDXID names. Packages from other tools count as binary
// packages.
func spdx2Role(id string) string {
	switch {
	case strings.HasPrefix(id, "SPDXRef-Recipe-"):
		return "recipe"
	case strings.HasPrefix(id, "SPDXRef-Image-"):
		return "rootfs"
	case strings.HasPrefix(id, "SPDXRef-Download-"):
		return "source"
	}
	return "package"
}

var cveID = regexp.MustCompile(`CVE-\d{4}-\d+`)

// spdx2Version returns a JSON document's spdxVersion, or "" if it has none.
func spdx2Version(raw []byte) string {
	var top struct {
		SpdxVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(raw, &top) != nil {
		return ""
	}
	return top.SpdxVersion
}

// isZstd reports whether head starts a zstd stream. Yocto compresses with pzstd, which starts
// with a skippable frame (magic 0x184D2A50 to 0x184D2A5F) instead of a normal one.
func isZstd(head []byte) bool {
	return bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}) ||
		(len(head) >= 4 && head[0]&0xf0 == 0x50 && bytes.Equal(head[1:4], []byte{0x2a, 0x4d, 0x18}))
}

// spdx2Docs reads SPDX 2.2 documents from a directory, a tar or .tar.zst, or a single file.
// ok is false when path is a single file that isn't SPDX 2.2, so Load tries SPDX 3.0 instead.
func spdx2Docs(path string) (docs []*spdx2Doc, ok bool, err error) {
	if py.IsDir(path) {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, true, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "index.json" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(path, e.Name()))
			if err != nil {
				return nil, true, err
			}
			if err := addSpdx2Doc(&docs, e.Name(), raw); err != nil {
				return nil, true, err
			}
		}
		return docs, true, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, false, err
	}
	switch {
	case isZstd(head):
		if _, err := exec.LookPath("zstd"); err != nil {
			return nil, true, fmt.Errorf("zstd is required to read %s", filepath.Base(path))
		}
		cmd := exec.Command("zstd", "-dcq")
		cmd.Stdin = f
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, true, err
		}
		if err := cmd.Start(); err != nil {
			return nil, true, err
		}
		docs, err = spdx2Tar(out)
		io.Copy(io.Discard, out) // let zstd finish before Wait
		if werr := cmd.Wait(); err == nil && werr != nil {
			err = fmt.Errorf("zstd: %w", werr)
		}
		return docs, true, err
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		docs, err = spdx2Tar(f)
		return docs, true, err
	}

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, false, err
	}
	if spdx2Version(raw) != spdx22Version {
		return nil, false, nil
	}
	err = addSpdx2Doc(&docs, filepath.Base(path), raw)
	return docs, true, err
}

func spdx2Tar(r io.Reader) ([]*spdx2Doc, error) {
	var docs []*spdx2Doc
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading the tar: %w", err)
		}
		name := filepath.Base(h.Name)
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(name, ".json") || name == "index.json" {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", h.Name, err)
		}
		if err := addSpdx2Doc(&docs, h.Name, raw); err != nil {
			return nil, err
		}
	}
}

// addSpdx2Doc parses one document. Every document in a set must be SPDX 2.2.
func addSpdx2Doc(docs *[]*spdx2Doc, name string, raw []byte) error {
	var d spdx2Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("%s: not JSON: %w", name, err)
	}
	if d.SpdxVersion != spdx22Version {
		v := d.SpdxVersion
		if v == "" {
			v = "a document without spdxVersion"
		}
		return fmt.Errorf("%s: %s isn't supported: %s", name, v, wantFormats)
	}
	*docs = append(*docs, &d)
	return nil
}

// loadSpdx2 builds the Sbom from a set of SPDX 2.2 documents.
func loadSpdx2(docs []*spdx2Doc) (*Sbom, error) {
	sort.SliceStable(docs, func(i, j int) bool { return docs[i].Name < docs[j].Name })
	sb := &Sbom{Packages: map[string]*Package{}, Generates: newIDList(), RuntimeDeps: newIDList(),
		BuildDeps: newIDList(), Vulns: newIDList(), vex: map[pair]string{}, vexNotes: map[pair]string{}, stated: map[pair]string{}, matched: map[pair]bool{}, nameOnly: map[pair]bool{}, fixes: map[pair]Fix{},
		assessed: map[pair]*Assessment{}, VulnInfo: map[string]*VulnInfo{}, Format: spdx22Format}
	if len(docs) > 1 {
		sb.Documents = len(docs)
	}
	loaded := map[string]bool{}
	for _, d := range docs {
		loaded[d.namespace()] = true
	}

	// First pass: packages, their files and fixed CVEs.
	missing := 0 // references to documents that aren't in the set
	for _, d := range docs {
		refs := d.refs()
		for _, ns := range refs {
			if !loaded[ns] {
				missing++
			}
		}
		files := map[string]File{}
		for _, f := range d.Files {
			var sha *string
			for _, c := range f.Checksums {
				if strings.EqualFold(c.Algorithm, "SHA256") {
					v := c.Value
					sha = &v
				}
			}
			files[f.ID] = File{Name: f.Name, Sha256: sha}
		}
		contains := map[string][]string{} // package SPDXID -> file SPDXIDs
		for _, r := range d.Relationships {
			if r.Type == "CONTAINS" {
				contains[r.From] = append(contains[r.From], r.To)
			}
		}
		for _, p := range d.Packages {
			id := d.global(p.ID, refs)
			if _, dup := sb.Packages[id]; dup {
				continue
			}
			pkg := &Package{ID: id, Name: p.Name, Version: p.Version, Role: spdx2Role(p.ID), Cpes: []string{}}
			if pkg.Name == "" {
				pkg.Name = p.ID
			}
			for _, r := range p.ExtRefs {
				switch {
				case strings.Contains(r.Type, "cpe"):
					pkg.Cpes = append(pkg.Cpes, r.Locator)
				case strings.HasSuffix(r.Type, "purl") && pkg.Purl == "":
					pkg.Purl = r.Locator
				}
			}
			seen := map[string]bool{}
			for _, fid := range append(append([]string{}, p.HasFiles...), contains[p.ID]...) {
				if f, ok := files[fid]; ok && !seen[fid] {
					seen[fid] = true
					pkg.Files = append(pkg.Files, f)
				}
			}
			if pkg.Role == "rootfs" && sb.Name == "" {
				sb.Name = d.Name
			}
			sb.Packages[id] = pkg
			sb.PackageOrder = append(sb.PackageOrder, id)

			if i := strings.Index(p.SourceInfo, "CVEs fixed:"); i >= 0 {
				set := map[string]bool{}
				for _, cve := range cveID.FindAllString(p.SourceInfo[i:], -1) {
					set[cve] = true
				}
				ids := make([]string, 0, len(set))
				for cve := range set {
					ids = append(ids, cve)
					sb.vex[pair{cve, id}] = "fixed"
					if sb.VulnInfo[cve] == nil {
						sb.VulnInfo[cve] = &VulnInfo{CVSS: map[string]*CVSS{}}
					}
				}
				sort.Strings(ids)
				if len(ids) > 0 {
					sb.Vulns.add(id, ids...)
				}
			}
		}
	}

	// Second pass: links between packages, which can cross documents.
	for _, d := range docs {
		refs := d.refs()
		for _, r := range d.Relationships {
			from, to := d.global(r.From, refs), d.global(r.To, refs)
			if sb.Packages[from] == nil || sb.Packages[to] == nil {
				continue
			}
			switch r.Type {
			case "GENERATED_FROM": // package built from recipe
				sb.Generates.add(to, from)
			case "RUNTIME_DEPENDENCY_OF", "DEPENDENCY_OF":
				sb.RuntimeDeps.add(to, from)
			case "DEPENDS_ON":
				sb.RuntimeDeps.add(from, to)
			case "BUILD_DEPENDENCY_OF":
				if sb.Packages[from].Role == "recipe" { // skip a recipe's downloads
					sb.BuildDeps.add(to, from)
				}
			}
		}
	}
	// Another tool's package that others are built from is a build component too.
	for _, src := range sb.Generates.Keys {
		if sb.Packages[src].Role == "package" {
			sb.Packages[src].Role = "recipe"
		}
	}

	if sb.Name == "" && len(docs) > 0 {
		sb.Name = docs[0].Name
	}
	for _, id := range sb.PackageOrder {
		if r := sb.Packages[id].Role; r == "package" || r == "recipe" {
			return sb, nil
		}
	}
	if missing > 0 {
		return nil, fmt.Errorf("this SPDX 2.2 document only points to %d others. For a Yocto image, pass "+
			"IMAGE.spdx.tar.zst from the image deploy directory, or a directory of its documents", missing)
	}
	return sb, nil
}
