<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/trowl-logo-dark.svg">
    <img src="assets/trowl-logo.svg" alt="Trowl" height="88">
  </picture>
</p>

<p align="center">
  <a href="https://trowl.dev"><img src="https://img.shields.io/badge/docs-trowl.dev-2f8cf0?style=flat" alt="Documentation"></a>
  <a href="https://github.com/corefense-security/trowl/tags"><img src="https://img.shields.io/github/v/tag/corefense-security/trowl?sort=semver&style=flat&label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/corefense-security/trowl?style=flat" alt="License"></a>
  <a href="https://trowl.dev/getting-started/docker/#verify-the-image"><img src="https://img.shields.io/badge/signed%20with-cosign-4b5563?style=flat" alt="Signed with Cosign"></a>
</p>

Trowl is a post-build security scanner for embedded Linux images. It unpacks the image and checks the kernel and userland for hardening gaps, misconfigurations and known CVEs.

Given an SBOM (`--sbom`), it compares its contents against what the image ships. With the matching kernel source (`--kernel-tree`), Trowl assigns VEX statuses to kernel CVEs and flags where they disagree with the SBOM.

<p align="center">
  <img src="assets/overview.png" alt="Trowl report overview of a Yocto core-image-minimal scan: key summary, unpatched CVEs, mounts, SBOM vs image and hardening coverage" width="900">
</p>

## What it checks
- Privileged binaries and compiler hardening (e.g., NX, CFI, PIE, stack protection)
- Kernel hardening (configurations, unsigned modules)
- Filesystem security
- Secrets and private keys
- SBOM dependencies and image discrepancies
- Known CVEs, fixes, available kernel backports
- SBOM VEX disagreements (e.g. code compiled but `.ko` module not shipped)

## Currently supported
- **Targets:** Yocto, Buildroot
- **Filesystems:** ext2/3/4, squashfs, tar, cpio (newc), or an unpacked directory.
- **Disk images:** `.wic` and other MBR/GPT images (ext or squashfs partitions). Scans the detected rootfs only.
- **Compression:** zstd, xz, gzip, bzip2, lz4.
- **SBOMs:** SPDX 2.2, SPDX 3.0 JSON-LD (including Yocto's `sbom-cve-check` output), and CycloneDX JSON (pass a separate CycloneDX VEX file with `--vex`).

### Local LLM (experimental)

Trowl uses local LLM to generate impact summaries. Model weights are downloaded from Hugging Face.

Supported models (licensed under Apache 2.0):

- [`qwen3-4b`](https://huggingface.co/Qwen/Qwen3-4B-GGUF)
- [`qwen3.5-4b`](https://huggingface.co/unsloth/Qwen3.5-4B-GGUF) (default and preferred)
- [`qwen3.5-9b`](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF)

## Quick start (Docker)

Assuming `/path/to/input` contains the scan targets (e.g. image, SBOM and kernel config):

```sh
docker run --rm -t \
  --user "$(id -u):$(id -g)" \
  -v /path/to/input:/in:ro \
  -v /path/to/output:/out \
  -v /path/to/kernel-source:/tree:ro \
  ghcr.io/corefense-security/trowl:$REF \
  scan /in/rootfs.ext4 \
    --sbom /in/sbom.spdx.json \
    --kernel-tree /tree \
    --kernel-config /in/kernel.config \
    -o /out/report
```
> [!TIP]
> Create `~/.cache/trowl` and pass `-v ~/.cache/trowl:/cache/trowl` to reuse downloaded CVE feeds and model weights.

> [!NOTE]
> `--kernel-tree`, `--kernel-config` and `--sbom` are optional, but enrich Trowl's VEX analysis.

Reports are saved under `/path/to/output/report/` (`index.html` and `report.json`). HTML reports can be viewed locally or via static hosting (GitHub Pages, Cloudflare Pages, S3).

For example:

```sh
python3 -m http.server 8765 --directory /path/to/output/report
```

### Verify the image

Release images are signed with [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/). With Cosign 3+ and Docker Buildx installed, replace `vX.Y.Z` with your release tag:

```sh
REF='vX.Y.Z'
IMAGE='ghcr.io/corefense-security/trowl'
DIGEST="$(docker buildx imagetools inspect "$IMAGE:$REF" --format '{{.Manifest.Digest}}')"

cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity "https://github.com/corefense-security/trowl/.github/workflows/build-release-trowl.yml@refs/tags/$REF" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Install

On Debian or Ubuntu (x86-64 or arm64):

```sh
# --with-llm is optional (Trowl skips AI summary)
curl -fsSL https://raw.githubusercontent.com/corefense-security/trowl/$REF/install.sh | bash -s -- --ref "$REF" --with-llm

# Scan image
trowl scan rootfs.ext4 --sbom /path/to/sbom.spdx.json \
      --kernel-config kernel.config \
      --kernel-tree /path/to/kernel-source -o report

# View report
trowl view report
```
Run `trowl scan --help` for all options.

> [!IMPORTANT]
> Until the first stable release, set `REF` to the latest preview tag in both the Docker and installer steps.


## External data

Trowl queries and caches relevant external resources:

- NVD, OSV and kernel CNA records
- CISA KEV, EPSS
- Model weights from Hugging Face

## Roadmap
- CI integration
- Build diffing for security regression
- License scanning
- Terminal reporting
- SBOM/VEX report generation
- More targets (Android, OpenWrt) and filesystems (EROFS, btrfs)

## Community

Trowl is under active development, and some features do not yet have automated tests. Test coverage will be expanded as the project matures.

Contributions and feedback are welcome. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

- [Open an issue](https://github.com/corefense-security/trowl/issues) for bugs or feature requests.
- Include reproduction steps and sanitized examples.
- Submit pull requests with a clear description of the changes.

## License

[Apache License 2.0](LICENSE).
