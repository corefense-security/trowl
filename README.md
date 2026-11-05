<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/trowl-logo-dark.svg">
    <img src="assets/trowl-logo.svg" alt="Trowl" height="88">
  </picture>
</p>

Trowl is a security scanner for embedded Linux images. It detects hardening gaps and known vulnerabilities.

Given an SBOM, it also maps dependencies and flags discrepancies.

## What it checks
- Privileged binaries and compiler hardening (e.g., NX, CFI, PIE, stack protection)
- Kernel hardening (configurations, unsigned modules)
- Filesystem security
- Secrets and private keys
- SBOM dependencies and image discrepancies
- Known CVEs, fixes, available kernel backports

## Currently supported
- **Distro:** Yocto
- **Filesystems:** ext2/3/4, squashfs, tar, or an unpacked directory.
- **Disk images:** `.wic` and other MBR/GPT images (ext or squashfs partitions). Scans the detected rootfs only.
- **Compression:** zstd, xz, gzip, bzip2.
- **SBOMs:** SPDX 3.0 JSON-LD from Yocto, including `sbom-cve-check` output.

### Local LLM (experimental)

Trowl uses a local LLM to generate impact summaries. Model weights are downloaded from Hugging Face and are licensed under Apache 2.0.

Supported models:

- [`qwen3-4b`](https://huggingface.co/Qwen/Qwen3-4B-GGUF) 
- [`qwen3.5-4b`](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF) (default and preferred)
- [`qwen3.5-9b`](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF)

## Quick start

From a directory containing your Yocto image and SBOM:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  ghcr.io/corefense-security/trowl:latest \
  scan image.ext4.zst --sbom image.spdx.json \
  -o report --cache-dir /work/.trowl-cache
```

Reports are saved under `report/index.html` and `report/report.json`.

Progress goes to stderr as plain `✓` and `✗` lines, so CI logs stay readable. Colour is on only in a terminal; set `FORCE_COLOR=1` to keep it in a log, or `NO_COLOR=1` to turn it off.

HTML reports can be viewed locally or via static hosting (GitHub Pages, Cloudflare Pages, S3). For example:

```sh
python3 -m http.server 8765 --directory report
```

Then open `http://localhost:8765` in your browser.

## Install

On Debian or Ubuntu (x86-64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/corefense-security/trowl/main/install.sh | bash
```

Then scan an image and open the report:

```sh
trowl scan image.ext4.zst -o report
trowl view report
```

For the optional local LLM summary, run the script with `--with-llm` to install `llama-server`:

```sh
curl -fsSL https://raw.githubusercontent.com/corefense-security/trowl/main/install.sh | bash -s -- --with-llm
```

Trowl then downloads the default model on the first scan; use `--model` to pick another. Without `llama-server`, the scan still runs and skips the summary.

Run `trowl scan --help` for all options.

## External data

Trowl queries and caches relevant external resources (`--no-network` uses the offline cache only):

- NVD, OSV and kernel CNA records
- CISA KEV, EPSS
- LLM models from Hugging Face

## Roadmap
- CI integration
- Build diffing for security regression
- License scanning
- Terminal reporting
- SBOM/VEX report generation
- Buildroot & OpenWrt support
- More filesystems (EROFS, btrfs)

## Community

Trowl is under active development, and some features do not yet have automated tests. Test coverage will be expanded as the project matures.

Contributions and feedback are welcome. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

- [Open an issue](https://github.com/corefense-security/trowl/issues) for bugs or feature requests.
- Include reproduction steps and sanitized examples.
- Submit pull requests with a clear description of the changes.

## License

[Apache License 2.0](LICENSE).
