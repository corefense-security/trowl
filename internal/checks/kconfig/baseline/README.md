# Kernel config baseline

One directory per mainline subsystem, named after the source directory whose Kconfig defines the
option (`security/`, `fs/`, `mm/`, `net/`, and `module/` for kernel/module). Each holds two lists:

- `harden.yaml`: options that add a protection (usually expected `y`)
- `attack_surface.yaml`: options that expose interfaces a device rarely needs (usually expected `n`)

Entry fields:

| field | meaning |
|---|---|
| `option` | Kconfig symbol without `CONFIG_` |
| `expect` | `y`, `n`, or `{min: N}` for numeric options |
| `since` | first mainline release that has the option (older kernels report "not applicable") |
| `arch` | architectures it exists on (`x86`, `arm64`, ...); omit for all |
| `why` | one line on what it protects or exposes |
| `ref` | where the expectation comes from: `mainline` (kernel/configs/hardening.config, v6.18) or `KSPP` |

Every entry is reviewed by a person. Teams override entries for their own images with
`--kernel-policy`, not by editing these files.
