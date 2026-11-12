# Package fingerprints

When an image has neither an SBOM nor a package database (a Yocto image built without
`package-management`, a Buildroot image), Trowl has no list of what is installed. These files let it
recover one from the binaries themselves: each says how to recognise one upstream package and its
version from strings its programs and libraries carry, and which CPE to match CVEs with.

Entries are chosen for embedded images. Only exact release strings are used: a package whose
binaries carry no reliable version is left out rather than guessed (see "Not detectable" below).

Results are package-level version matches: a version string can't show a CVE patch backported
without a version change, so the report says so and recommends `--sbom`.

## Format

One YAML file per upstream package, named after it:

```yaml
package: openssh                      # the name the report shows
cpes: [cpe:2.3:a:openbsd:openssh]     # vendor:product as NVD files CVEs; "*" for any vendor
evidence:                             # tried in order; the first that gives a version wins
  - files: [sshd, ssh.*]              # file-name globs (path.Match), matched anywhere in the rootfs
    pattern: '\x00OpenSSH_(?P<version>\d+\.\d+p\d+)\x00'   # over the file's bytes
  - files: [liblzma.so.*]
    name_pattern: '^liblzma\.so\.(?P<version>\d+\.\d+\.\d+)$'  # over the file name instead
examples:                             # checked by the tests; at least one per file
  - file: sshd
    contains: "command-line\0OpenSSH_10.3p1\0%s, %s"
    version: 10.3p1
rejects:                              # optional: strings that must not match
  - file: sshd
    contains: "\0OpenSSH_3.*\0"
```

- Only ELF files are read, and only those whose name matches a glob. Symbolic links are skipped:
  the file they point to is read under its own name.
- A pattern must have a named group `version`. Anchor it on what surrounds the version in the
  binary (NUL bytes, fixed words) so it can't pick up an unrelated number. For a version stored as
  packed digits, use `major`, `minor` and `patch` groups instead: they are joined with dots and
  lose leading zeros (`2`, `3`, `02` is 2.3.2).
- The version must be in the form the CVE data uses (`10.3p1`, `1.1.1w`). A trailing Yocto
  suffix such as `+git` is dropped.
- List every vendor the CVE records use. NVD's CPE vendor and the CNA's vendor field can differ
  (util-linux is `kernel` in NVD, `util-linux` in its own advisories), and a CVE NVD hasn't
  analysed yet only has the CNA's. A loose spelling is fine: "The GNU C Library" agrees with `gnu`.
- `/usr/src/debug/<recipe>/<version>/` is Yocto's debug prefix in source file names compiled into
  assert and error messages. It names the recipe and version exactly, so it is used where a
  package prints no version of its own. It is only present in Yocto builds.

To add a package: find the string in a real binary (`grep -a -o` or `strings`), write the file,
copy the bytes around the version into `examples`, and run `go test ./internal/inventory/`.

## Packages

Chosen from the binaries in a Yocto core-image-minimal (wrynose, x86-64):

| File | Evidence |
|---|---|
| busybox.yaml | `BusyBox v1.37.0` |
| glibc.yaml | `GNU C Library (GNU libc) stable release version 2.43` |
| openssh.yaml | `OpenSSH_10.3p1` |
| openssl.yaml | `OpenSSL 3.5.9 29 Sep 2026` |
| zlib.yaml | `deflate 1.3.2 Copyright` |
| util-linux.yaml | `util-linux 2.41.6`, or in libblkid `2.39.3` next to `04-Dec-2023`, or the Yocto debug path in its libraries |
| xz.yaml | the library's file name, `liblzma.so.5.8.2` |
| acl.yaml | the library's file name, `libacl.so.1.1.2302` (revision 2302 is 2.3.2) |
| attr.yaml | the library's file name, `libattr.so.1.1.2502` (revision 2502 is 2.5.2) |
| kmod.yaml | `kmod version 34.2`, Yocto debug path |
| sysvinit.yaml | `INIT_VERSION=sysvinit-3.14` |
| tar.yaml | Yocto debug path only |
| shadow.yaml | Yocto debug path only |
| eudev.yaml | Yocto debug path only |
| libxcrypt.yaml | Yocto debug path only |

## Not detectable

Packages in that image with no reliable version in their binaries, so not listed:

- **GNU tar outside Yocto**: `tar --version` builds its text at run time; the only literal
  `1.x` strings in the binary are unrelated (one reads `GNU tar 1.13`).
- Script-only or data-only recipes (base-files, initscripts, netbase, update-rc.d, opkg-utils)
  have no binaries to read.
