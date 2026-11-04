<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/trowl-logo-dark.svg">
    <img src="assets/trowl-logo.svg" alt="Trowl" height="88">
  </picture>
</p>

# Trowl

**See what actually shipped.** Trowl is an offline, static analyser for embedded Linux
images. Point it at a firmware image, and optionally the SBOM your build produced, and it tells
you:

- **where the image's hardening falls short**: binaries built without PIE, NX, RELRO, stack
  canaries or `_FORTIFY_SOURCE`, and writable mounts missing `nodev`/`nosuid`/`noexec`
- **what secrets were left in it**: private keys, SSH host keys baked into the image, and cloud
  or CI tokens
- **where the SBOM and the image disagree**: packages the SBOM lists but the image doesn't
  contain, and the CVEs attached to components that never reach the device

The results come as a JSON report for machines and a single self-contained HTML page for people,
including an interactive SBOM dependency graph.

trowl never boots, mounts or executes the image. It needs no root, no network and no device,
so it runs the same on a laptop as in a CI job.

> **Status:** early development (pass 1). Yocto / AGL images are the first target; Buildroot and
> OpenWrt follow. Output formats may still change.

## Quick start

```sh
docker run --rm -p 8765:8765 -v "$PWD:/work" -v trowl-cache:/cache \
  ghcr.io/corefense/trowl:latest \
  scan core-image-minimal-qemux86-64.rootfs.ext4.zst \
  --sbom core-image-minimal-qemux86-64.rootfs.sbom-cve-check.spdx.json \
  -o report --serve
```

Each scan writes a static dashboard: `report/index.html` (one self-contained file) and
`report/report.json` for your own tooling. With `--serve` the container then serves the folder at
http://localhost:8765; without it, the scan just writes the files (the usual CI case). Open the
HTML directly, or publish the folder on any static host (GitLab/GitHub Pages, an artifact browser,
S3).

During the scan the container fetches what it needs: the CISA KEV catalogue, EPSS scores, a check
that each advisory link exists, and on first use the local model that writes the Overview summary
(Qwen3 4B by default, about 2.5 GB, run on CPU with llama.cpp). All of it is cached in `/cache`; mount a
volume there, as above, so later runs reuse it. `--no-network` skips the fetches.

Without Docker:

```sh
go install github.com/corefense/trowl/cmd/trowl@latest
# needs debugfs (e2fsprogs), unsquashfs, zstd on PATH; llama.cpp's llama-server for the model
trowl scan IMAGE [--sbom SBOM.spdx.json] [-o DIR] [--fail-on high] [--serve]
                 [--kernel-config FILE] [--kernel-src DIR] [--kernel-policy FILE]
                 [--model qwen3-4b|qwen3-1.7b] [--links open|all|none] [--no-network] [--cache-dir DIR]
trowl unpack IMAGE DEST      # just extract the root filesystem
trowl view [DIR]             # preview a report folder at http://127.0.0.1:8765 (no caching)
```

## Inputs

| Input | Supported |
|---|---|
| Root filesystem | ext2/3/4, squashfs, tar, or an already-unpacked directory |
| Disk images | `.wic` and other MBR/GPT images; the partition that looks like a rootfs is analysed |
| Compression | zstd, xz, gzip, bzip2 (detected from the file's contents, not its name) |
| SBOM | SPDX 3.0 JSON-LD (Yocto `create-spdx`, including the `sbom-cve-check` variant) |

The image is unpacked with `debugfs`/`unsquashfs` in user space. Device nodes, and archive
entries that would escape the output directory, are skipped.

## What it checks (pass 1)

| Area | Check |
|---|---|
| Binaries | PIE, NX stack, RELRO (none / partial / full), stack protector, `_FORTIFY_SOURCE`, insecure RPATH/RUNPATH; CET (x86) and BTI/PAC (arm64) properties are shown in the report |
| Secrets | PEM/OpenSSH/PuTTY private keys (encrypted vs not), SSH host keys baked into the image, AWS/GitHub/GitLab/Slack/Google tokens. Matches are redacted to a short preview plus a SHA-256 |
| Mounts | `/etc/fstab`: missing `nodev`/`nosuid`/`noexec` on writable mounts, read-write root |
| SBOM vs image | Each package's declared files (path and SHA-256) are checked against the image, so no package database is needed in the image. Packages are reported as present, changed, partial or absent; recipes as shipped or build-time only. CVEs attached to absent or build-only components are listed as VEX `component_not_present` candidates |

The SBOM comparison works at package level. A package being absent says nothing about copies of
its code that were statically linked or vendored into another package.

## The dashboard

`index.html` is a static, offline dashboard built from the scan. It follows the viewer's light or
dark preference and has a toggle to switch.

- **Overview**: up to four key points on the image's security status, written by the local model
  from this scan's results only; KPI tiles (fully hardened binaries, secrets, SBOM drift, CVEs not in
  image), hardening coverage per protection and the SBOM-vs-image breakdown
- **Filesystems**: the `/etc/fstab` mounts with their `ro`/`nodev`/`nosuid`/`noexec` flags, and every
  private key, baked-in host key or token found, listed under the mount point that holds it
- **Kernel**: the kernel config (read from `/boot/config-*`, or the copy embedded in the kernel
  image) checked against trowl's baseline in `internal/checks/kconfig/baseline/`, per subsystem
  (security, fs, mm, net) in two lists: attack surface reduction and hardening. Teams accept
  deviations, with a required reason, or add their own checks with `--kernel-policy`
- **Binary**: sortable hardening matrix for every executable and library
- **SBOM**: an interactive workspace for recipes and packages
  - nodes coloured by whether they reached the image and sized by file count, with a ring on
    nodes that have open CVEs
  - layered, radial and force layouts
  - search with suggestions, status filters, and optional build-time recipes and build
    dependencies
  - click a node to highlight what it depends on (blue) and what requires it (orange), and to
    open a detail panel with its relations, file differences, CVEs and identifiers
  - a table view of the same data, and PNG export
- **CVEs**: every CVE the SBOM attaches to a component, with its status from the SBOM
  (unpatched, ignored, fixed), CVSS score and attack vector, whether its package ships or is
  build-time only, and whether it is in CISA KEV. A CVE only stops mattering for the image when
  none of the packages that carry it ship. Clicking a row opens the SBOM's description, EPSS and
  verified NVD / OSV / CNA links

## In CI

Scans are static: each run produces files and nothing needs to stay running. `--fail-on <severity>`
exits with code 1 when any finding is at or above that severity. Keep the output folder as a
build artifact, or publish it with Pages so every pipeline has a browsable dashboard.
Ready-to-copy jobs:

- GitHub Actions: [`ci/github-actions.example.yml`](ci/github-actions.example.yml)
- GitLab CI: [`ci/gitlab-ci.example.yml`](ci/gitlab-ci.example.yml)

## Development

```sh
cd ui && npm ci && npm run build && cd ..   # writes internal/report/ui/index.html (embedded by go build)
go build -o bin/trowl ./cmd/trowl
bin/trowl scan path/to/rootfs -o /tmp/report
```

`go install` gives a binary without the dashboard unless the UI was built first; the release
binaries and the container image always include it. The model runs through llama.cpp's
`llama-server`, found on `PATH` or at `$TROWL_LLAMA_SERVER`.

Layout: `cmd/trowl` (CLI), `internal/unpack` (image → directory), `internal/checks/` (one
package per check family; the kernel baseline lists live in `internal/checks/kconfig/baseline/`),
`internal/sbom` (SPDX 3.0 reader, SBOM-vs-image comparison, CVE rows), `internal/feeds` (KEV,
EPSS, advisory links), `internal/llm` (local model), `internal/scan` (orchestration),
`internal/report` (JSON + HTML), `ui/` (React + Cytoscape.js viewer, built into one HTML file).

## Roadmap

Next passes add more checks (accounts, enabled services, kernel config and command line,
boot chain), and adapters for Buildroot and OpenWrt images.

## License

Apache License 2.0. See [LICENSE](LICENSE).
