# Binary fingerprints

Trowl uses this technique as a fallback mechanism when no SBOM is provided, or the image lacks a package database. Each file tells Trowl how
to recognise an installed userland package, its version and the CPE to look up CVEs with.

> Note: Fingerprinting can't detect a patch backported without a version change. Pass `--sbom`
when you have one.

## Example
Fingerprints are maintained in a YAML format.

```yaml
package: openssh
cpes: [cpe:2.3:a:openbsd:openssh]
evidence:
  - files: [sshd, ssh.*]
    pattern: '\x00OpenSSH_(?P<version>\d+\.\d+p\d+)\x00'
examples:                             # for the tests only
  - file: sshd
    contains: "command-line\0OpenSSH_10.3p1\0%s, %s"
    version: 10.3p1
rejects:                              # for the tests only
  - file: sshd
    contains: "\0OpenSSH_3.*\0"
```

## Scan Format

Trowl reads these fields to detect a package and its version, and then match CVEs against its CPEs.

| Field | Required | Meaning | Example |
|---|---|---|---|
| `package` | yes | Package name shown in the report | `openssh` |
| `cpes` | yes | CPE prefix for each vendor that files CVEs against the package. Trowl appends the detected version. Use `*` to match any vendor | `[cpe:2.3:a:openbsd:openssh]` |
| `evidence` | yes | Ordered sequence of options to detect a package's version. The first match wins | |
| `evidence[].files` | yes | File name globs in `path.Match` syntax. Trowl checks matching ELF files anywhere in the rootfs | `[sshd, ssh.*]` |
| `evidence[].pattern` | yes, unless `name_pattern` is set | Regex run over the file contents. It needs a `version` group | `'\x00OpenSSH_(?P<version>\d+\.\d+p\d+)\x00'` |
| `evidence[].name_pattern` | instead of `pattern` when the version is in the file name | Regex run over the file name instead of its contents | `'^liblzma\.so\.(?P<version>\d+\.\d+\.\d+)$'` |

## Test Format

These are only used by `go test ./internal/inventory/`. Trowl ignores them during a scan, but skips a file without at least one example.

| Field | Required | Meaning | Example |
|---|---|---|---|
| `examples` | yes | Inputs that must produce a version. Add one per evidence entry | |
| `examples[].file` | yes | File name the input stands for | `sshd` |
| `examples[].contains` | yes | Bytes copied from a real binary. Double quotes turn `\0` and `\x0a` into real bytes | `"command-line\0OpenSSH_10.3p1\0%s, %s"` |
| `examples[].version` | yes | Version the fingerprint must return | `10.3p1` |
| `rejects` | no | Inputs that must produce no version. Same fields as `examples` minus `version` | `{file: sshd, contains: "\0OpenSSH_3.*\0"}` |

## Adding a package

1. Find the version in a real binary with `strings` or `grep -a -o`.
2. Write `<package>.yaml` and copy the bytes around the version into `examples`.
3. Run `go test ./internal/inventory/`.

## More

See [Binary fingerprinting](https://trowl.dev/features/cves-vex/fingerprints/) for more details.
