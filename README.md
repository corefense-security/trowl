<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/trowl-logo-dark.svg">
    <img src="assets/trowl-logo.svg" alt="Trowl" height="88">
  </picture>
</p>


Trowl is a static security analyser for embedded Linux images. It unpacks a rootfs to detect hardening gaps, known CVEs, and hidden secrets to 
provide a comprehensive post-build security posture analysis. 

When provided with an SBOM, it can also perform dependency analysis.


## What it checks
- Hardening gaps (binaries, kernel, filesystems)
- Secrets and private keys
- Software-Bill-of-Materials (SBOM) analysis, including graph-based relationships and image discrepancies
- Known CVEs


## Currently supported
- **Distro:** Yocto 
- **Filesystems:** ext2/3/4, squashfs, tar, or an unpacked directory.
- **Disk images:** `.wic` and other MBR/GPT images; one detected root filesystem is analysed (ext or squashfs partitions only; extended MBR partitions are skipped).
- **Compression:** zstd, xz, gzip, bzip2.
- **SBOMs:** SPDX 3.0 JSON-LD from Yocto, including `sbom-cve-check` output.

## Quick start

From a directory containing your image and SBOM:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8765:8765 -v "$PWD:/work" \
  ghcr.io/corefense-security/trowl:latest \
  scan <image>.ext4.zst --sbom <image>.spdx.json \
  -o report --cache-dir /work/.trowl-cache --serve
```

Reports are saved under `report/index.html` and `report/report.json`.

HTML reports can be viewed independently of Trowl, either locally or through static hosting (GitHub Pages, Cloudflare Pages, S3).

For example, serve the report locally using Python:

```sh
python3 -m http.server 8765 --directory report
```

Then open `http://localhost:8765` in your browser.

## External data
Trowl queries various resources both before and during a scan.
- CISA KEV,
- EPSS,
- Advisories (NVD, CNA)

## Local LLM usage (experimental)

We intend to run local LLM inferencing for a variety of use cases.

- Impact summaries
- Image and report diffing summaries

### Supported models: 
- Qwen 3-4B (default and preferred)
- Qwen 3.5-4B
- Qwen 3.5-9B 

Model downloads are cached. `--no-network` disables feed and link requests but currently
does not prevent an uncached model download.

Run `trowl scan --help` for kernel configuration, policy, model, and other options.


## Development

Requires Go 1.23+, Node.js and npm. Image extraction uses `debugfs`,
`unsquashfs`, and `zstd` as needed. Reading an rpm database uses `sqlite3`.

```sh
cd ui && npm ci && npm run build && cd ..
go build -o bin/trowl ./cmd/trowl
bin/trowl scan path/to/rootfs -o report
```

Build the UI before the Go binary to include the dashboard.
The local summary additionally requires llama.cpp’s `llama-server`.

## Roadmap
- CI Integration
- Image and report diffing
- License scanning
- Terminal reporting
- SBOM and VEX generation
- Backport detection (Kernel CVEs)
- Buildroot & OpenWrt support

## Community

Trowl is under active development, and some features do not yet have automated tests. Test coverage will be expanded as the project matures.

Contributions and feedback are welcome.

- [Open an issue](https://github.com/corefense-security/trowl/issues) for bugs or feature requests.
- Include reproduction steps and sanitized examples.
- Submit pull requests with a clear description of the changes.

## License

[Apache License 2.0](LICENSE).