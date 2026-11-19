# Scan each image with Trowl once the build has finished.
#
#   INHERIT += "trowl"
#
# Trowl is a post-build scanner. The class doesn't add tasks to an image or change its
# signatures, sstate or output. It does two things.
#   1. Images also depend on trowl-native in their do_build, which runs nothing. So one
#      "bitbake <image>" builds Trowl as well.
#   2. When the build succeeds, a handler reads each built image's testdata.json from the
#      deploy dir, works out the rootfs, SBOM and kernel paths, and runs trowl scan.
# Reports go to TROWL_REPORT_DIR. Nothing is written into TMPDIR.

# Where reports go, one directory per image.
TROWL_REPORT_DIR ??= "${TOPDIR}/trowl"
# "0" turns the scan off.
TROWL_SCAN ??= "1"
# An image is scanned again only when it is newer than its report. "1" scans every build.
TROWL_ALWAYS ??= "0"
# Rootfs types Trowl reads, in the order the class looks for them.
TROWL_FSTYPES ??= "ext4 ext4.zst ext4.xz ext4.gz ext4.bz2 ext3 ext2 squashfs squashfs-xz squashfs-zst \
    squashfs-lz4 squashfs-lzo tar.zst tar.xz tar.bz2 tar.gz tar cpio.zst cpio.xz cpio.gz cpio.lz4 cpio \
    wic wic.zst wic.xz wic.gz wic.bz2"
# SBOMs in the order the class prefers them.
TROWL_SBOM_NAMES ??= ".sbom-cve-check.spdx.json .spdx.json .spdx.tar.zst"
# A kernel source tree and .config to scan with, for builds that restore the kernel from sstate
# and so have no work-shared copy. They replace STAGING_KERNEL_DIR and STAGING_KERNEL_BUILDDIR.
# Relative paths are from TOPDIR. The tree must match the image's kernel.
TROWL_KERNEL_TREE ??= ""
TROWL_KERNEL_CONFIG ??= ""
# "1" builds llama-server, fetches the model and lets Trowl write its Overview summary. The
# model is a 2.7 GB download, so this is off by default. TROWL_LLM_MODEL picks the model.
TROWL_LLM ??= "0"

# Native tools the scan runs. They are built with the image and run from sysroots-components.
TROWL_NATIVE_DEPS = "trowl-native e2fsprogs-native squashfs-tools-native zstd-native xz-native lz4-native lzop-native"

python () {
    if d.getVar("TROWL_SCAN") != "1" or not bb.data.inherits_class("image", d):
        return
    deps = ["%s:do_populate_sysroot" % r for r in d.getVar("TROWL_NATIVE_DEPS").split()]
    if d.getVar("TROWL_LLM") == "1":
        deps += ["trowl-llama-native:do_populate_sysroot", "trowl-model-native:do_fetch"]
    d.appendVarFlag("do_build", "depends", " " + " ".join(deps))
}

def trowl_testdata(deploy, target):
    """The image's own variables from <target>-<machine>...testdata.json, or None."""
    import glob, json, os
    for path in sorted(glob.glob(os.path.join(deploy, target + "-*.testdata.json"))):
        if os.path.islink(path):
            with open(path) as f:
                vars = json.load(f)
            if vars.get("PN") == target:
                return vars
    return None

def trowl_inputs(e, vars):
    """The trowl scan arguments for one image, or a reason to skip it."""
    import os
    topdir = e.data.getVar("TOPDIR")
    at = lambda p: os.path.join(topdir, p) if p and not os.path.isabs(p) else p
    deploy = at(vars["DEPLOY_DIR_IMAGE"])
    link = vars["IMAGE_LINK_NAME"]

    built = (vars.get("IMAGE_FSTYPES") or "").split()
    image = ""
    for t in e.data.getVar("TROWL_FSTYPES").split():
        if t in built and os.path.exists(os.path.join(deploy, link + "." + t)):
            image = os.path.join(deploy, link + "." + t)
            break
    if not image:
        return None, "no rootfs Trowl reads. IMAGE_FSTYPES is \"%s\"" % " ".join(built)

    args = [image]
    for name in e.data.getVar("TROWL_SBOM_NAMES").split():
        if os.path.exists(os.path.join(deploy, link + name)):
            args += ["--sbom", os.path.join(deploy, link + name)]
            break
    else:
        bb.warn("Trowl: no SBOM for %s, so only the image is scanned" % link)

    # TROWL_KERNEL_CONFIG and TROWL_KERNEL_TREE win. Otherwise the work-shared copies are used,
    # which are there only when the kernel was built in this TMPDIR.
    config = at(e.data.getVar("TROWL_KERNEL_CONFIG"))
    if config:
        if not os.path.isfile(config):
            bb.warn("Trowl: TROWL_KERNEL_CONFIG %s isn't a file, so it isn't used" % config)
            config = ""
    else:
        config = os.path.join(at(vars.get("STAGING_KERNEL_BUILDDIR") or ""), ".config")
        if not os.path.isfile(config):
            config = ""
    if config:
        args += ["--kernel-config", config]
    else:
        bb.warn("Trowl: no kernel config for %s, so Trowl uses one the image carries if any" % link)

    tree = at(e.data.getVar("TROWL_KERNEL_TREE"))
    if tree:
        if not os.path.isfile(os.path.join(tree, "Makefile")):
            bb.warn("Trowl: TROWL_KERNEL_TREE %s isn't a kernel tree, so it isn't used" % tree)
            tree = ""
    else:
        tree = at(vars.get("STAGING_KERNEL_DIR") or "")
        if not os.path.isfile(os.path.join(tree, "Makefile")):
            tree = ""
    if tree:
        args += ["--kernel-tree", tree]
    else:
        bb.warn("Trowl: no kernel source for %s, so kernel CVEs stay version matches" % link)
    return args, ""

def trowl_run(e, link, args):
    import os, subprocess
    data = e.data
    report = os.path.join(data.getVar("TROWL_REPORT_DIR"), link)
    components = os.path.join(data.getVar("COMPONENTS_DIR"), data.getVar("BUILD_ARCH"))
    trowl = os.path.join(components, "trowl-native", "usr", "bin", "trowl")
    if not os.path.exists(trowl):
        bb.warn("Trowl: %s isn't built, so %s isn't scanned" % (trowl, link))
        return

    # Scan again only when the image is newer than the report.
    image = os.path.realpath(args[0])
    done = os.path.join(report, "report.json")
    if data.getVar("TROWL_ALWAYS") != "1" and os.path.exists(done) and \
            os.path.getmtime(done) > os.path.getmtime(image):
        bb.plain("Trowl: %s hasn't changed since %s/index.html" % (link, report))
        return

    cmd = [trowl, "scan"] + args + ["-o", report]
    if data.getVar("BB_NO_NETWORK") == "1":
        cmd.append("--no-network")

    paths = [os.path.join(components, r, "usr", b) for r in data.getVar("TROWL_NATIVE_DEPS").split() for b in ("bin", "sbin")]
    env = dict(os.environ, PATH=os.pathsep.join([p for p in paths if os.path.isdir(p)] + [os.environ.get("PATH", "")]))
    cmd += trowl_llm(data, components, env)

    bb.plain("Trowl: scanning %s" % link)
    os.makedirs(report, exist_ok=True)
    with open(os.path.join(report, "scan.log"), "w") as log:
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in proc.stdout:
            log.write(line)
            lines.append(line.rstrip())
            bb.note("trowl: " + line.rstrip())
    if proc.wait() != 0:
        bb.warn("Trowl: the scan of %s failed. See %s/scan.log\n%s" % (link, report, "\n".join(lines[-10:])))
        return
    summary = " ".join(l for l in lines if l.startswith(("findings:", "sbom:")))
    bb.plain("Trowl: %s/index.html %s" % (report, summary))

def trowl_llm(data, components, env):
    """The model flags for trowl scan. They point Trowl at the built llama-server and the
    fetched model, or turn the summary off."""
    import os
    if data.getVar("TROWL_LLM") != "1":
        return ["--no-llm"]
    name = data.getVar("TROWL_LLM_MODEL")
    entry = data.getVarFlag("TROWL_LLM_MODELS", name) or ""
    server = os.path.join(components, "trowl-llama-native", "usr", "bin", "llama-server")
    model = os.path.join(data.getVar("DL_DIR"), entry.split()[0]) if entry else ""
    for path in (server, model):
        if not path or not os.path.exists(path):
            bb.warn("Trowl: %s isn't there, so the scan has no summary" % (path or "TROWL_LLM_MODEL " + name))
            return ["--no-llm"]
    env["TROWL_LLAMA_SERVER"] = server
    env["TROWL_MODEL_FILE"] = model
    return ["--model", name]

addhandler trowl_scan
trowl_scan[eventmask] = "bb.event.BuildCompleted"
python trowl_scan() {
    if e.data.getVar("TROWL_SCAN") != "1" or e.getFailures():
        return
    deploy = e.data.getVar("DEPLOY_DIR_IMAGE")
    for target in e.getPkgs():
        # A plain recipe name, not mc:... or target:do_task.
        if ":" in target:
            continue
        vars = trowl_testdata(deploy, target)
        if not vars:
            continue
        args, why = trowl_inputs(e, vars)
        if why:
            bb.warn("Trowl: %s isn't scanned: %s" % (target, why))
            continue
        trowl_run(e, vars["IMAGE_LINK_NAME"], args)
}
