# Kernel config baseline

Trowl uses these baselines to check the image's kernel configurations for missing hardening protections and enabled features that increase the attack surface.

Checks are grouped by purpose under `security/`, `fs/`, `mm/` (memory), `net/`, `module/`,
`kernel/`, `compiler/`, `platform/` and `tty/`. Architecture checks live under `arch/`,
with separate directories for ARM, ARM64 and x86 variants. Each directory can hold two lists:

- `harden.yaml`: options that add a protection (usually expected `y`)
- `attack_surface.yaml`: options that expose interfaces a device rarely needs (usually expected `n`)

Entry fields:

| field | meaning |
|---|---|
| `option` | Kconfig symbol without `CONFIG_` |
| `expect` | `y`, `n`, a string, an integer, or `{min: N}` for a numeric minimum |
| `since` | first mainline release that has the option (older kernels report "not applicable") |
| `arch` | Target architectures as an array; omit for shared checks. `x86` covers both variants; use `x86_32` or `x86_64` to select one. Other names include `arm` and `arm64`. |
| `why` | one line on what it protects or exposes |
| `ref` | where the expectation comes from: `mainline` (kernel/configs/hardening.config, v6.18) or `KSPP` |

Every entry is reviewed by a person. Teams override entries for their own images with
`--kernel-policy`, not by editing these files.

The scanner detects the architecture once. The `arch` field controls applicability;
directory names only organize the checks. Register new directories in `Subsystems` in `kconfig.go`.

The KSPP additions follow its [current CONFIG recommendations](https://kspp.github.io/Recommended_Settings#configs).
Historical names and superseded recommendations are excluded. Checks remain independent:
compiler, hardware and option dependencies are not evaluated. A missing option keeps the
existing missing result, and some recommendations are alternatives, such as disabling modules
or requiring signatures when modules are enabled. Boot arguments and sysctls are outside this baseline.
