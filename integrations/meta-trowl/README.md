# meta-trowl

Scans each Yocto image with [Trowl](../../README.md) once BitBake has built it.

Tested on Scarthgap (5.0) and Wrynose with `core-image-minimal` for `qemux86-64`.

## Use

Add the layer and inherit the class in `local.conf`:

```sh
bitbake-layers add-layer /path/to/trowl/integrations/meta-trowl
echo 'INHERIT += "trowl"' >> conf/local.conf
bitbake core-image-minimal
```

One `bitbake` builds Trowl, builds the image and scans it. Adding the layer alone changes nothing.

When the build finishes, the scan prints where the report is:

```
Trowl: scanning core-image-minimal-qemux86-64.rootfs
Trowl: .../build/trowl/core-image-minimal-qemux86-64.rootfs/index.html findings: ...
```

## How it stays out of the build

Trowl is a post-build scanner. The class doesn't add tasks to an image or change its signatures,
sstate or output.

- Images also depend on `trowl-native` in their `do_build`, which runs nothing. That is how one
  `bitbake` builds Trowl too.
- The scan runs in a handler after the build succeeds. A failed build isn't scanned.
- Reports go to `${TOPDIR}/trowl/<image>/`. Nothing is written into `TMPDIR`.
- An image is scanned again only when it is newer than its report.

## Where the paths come from

Every image build writes `<image>.testdata.json` to the deploy dir with the image's own
variables. The handler reads it for each image on the `bitbake` command line.

| Trowl flag | From | When it's missing |
|---|---|---|
| image | `IMAGE_LINK_NAME` and the first of `TROWL_FSTYPES` in `IMAGE_FSTYPES` | Warning, and the image isn't scanned |
| `--sbom` | `.sbom-cve-check.spdx.json`, then `.spdx.json` (SPDX 3.0), then `.spdx.tar.zst` (SPDX 2.2) | Warning, and only the image is scanned |
| `--kernel-config` | `TROWL_KERNEL_CONFIG`, else `STAGING_KERNEL_BUILDDIR/.config` | Warning, and Trowl uses a config the image carries if any |
| `--kernel-tree` | `TROWL_KERNEL_TREE`, else `STAGING_KERNEL_DIR` | Warning, and kernel CVEs stay version matches |

Scarthgap writes SPDX 2.2 by default and Wrynose writes SPDX 3.0. With the `core/yocto/sbom-cve-check`
fragment, Wrynose also writes the `sbom-cve-check` SPDX, which the class prefers.

The kernel config and source exist when the kernel was built in this `TMPDIR`. A kernel that came
from sstate has neither. Set `TROWL_KERNEL_TREE`, `TROWL_KERNEL_CONFIG` or both to a tree and
config that match the image's kernel. Each is optional and replaces only its own input.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `TROWL_SCAN` | `1` | `0` turns the scan off |
| `TROWL_REPORT_DIR` | `${TOPDIR}/trowl` | Where reports go, one directory per image |
| `TROWL_ALWAYS` | `0` | `1` scans every build, not only when the image changed |
| `TROWL_FSTYPES` | ext4, squashfs, tar, cpio and wic variants | Rootfs types the class looks for, in order |
| `TROWL_SBOM_NAMES` | see above | SBOM names the class looks for, in order |
| `TROWL_KERNEL_TREE` | empty | Kernel source tree to use instead of `STAGING_KERNEL_DIR` |
| `TROWL_KERNEL_CONFIG` | empty | Kernel `.config` to use instead of the one in `STAGING_KERNEL_BUILDDIR` |
| `TROWL_LLM` | `0` | `1` builds `llama-server`, fetches the model and adds the Overview summary |
| `TROWL_LLM_MODEL` | `qwen3.5-4b` | `qwen3-4b`, `qwen3.5-4b` or `qwen3.5-9b` |

With `BB_NO_NETWORK = "1"` the scan runs with `--no-network` and needs a filled `~/.cache/trowl`.

## The Overview summary

With `TROWL_LLM = "1"` in `local.conf` the same `bitbake` also builds `trowl-llama-native`
(llama.cpp's `llama-server`) and fetches the model into `DL_DIR`, checked against its SHA-256.
The model is a 2.7 GB download for the 4B models, so the summary is off by default. With it off
the scan runs with `--no-llm`.

`llama-server` is built with every CPU variant as a loadable backend and picks the best one at
runtime. A build for one CPU couldn't be shared through sstate.

## How trowl-native builds

`trowl-native` builds the Trowl commit pinned in its `SRCREV`, whichever branch of the layer is
checked out. One recipe serves both releases.

- Go 1.26 and Node 22 come pinned in the recipe, like `install.sh` pins them. Scarthgap ships
  Go 1.22 and neither release ships Node.
- Go modules come from the Go proxy as plain downloads, checked against `go.sum`. Scarthgap has
  no gomod fetcher.
- The dashboard's npm packages come from `files/package-lock.json`, a copy of the pinned commit's
  `ui/package-lock.json`, each checked against its sha512. Wrynose disables the npmsw fetcher, so
  the tarballs are fetched one by one.
- A bump sets `SRCREV`, copies that commit's `ui/package-lock.json` to `files/`, and updates
  `TROWL_GOMODS` when its `go.sum` changed.

## Known issues

Wrynose with `rm_work` and the `sbom-cve-check` fragment fails in its own `do_sbom_cve_check` on
a rebuild. This happens with or without the layer. `rm_work` drops the stamps of the
`sbom-cve-check-update-*-native` recipes, so they rerun and `do_sbom_cve_check` reruns with a new
`DATETIME`. It then reads `${IMAGE_NAME}.spdx.json` for an image that wasn't rebuilt. The build
fails before it finishes, so Trowl doesn't scan. `bitbake -c cleansstate core-image-minimal`
gets a clean build again.
