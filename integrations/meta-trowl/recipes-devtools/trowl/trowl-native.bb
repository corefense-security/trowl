SUMMARY = "Trowl security and CVE scanning"
HOMEPAGE = "https://github.com/corefense-security/trowl"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=86d3f3a95c324c9479bd8986968f4327"

inherit native

PV = "0.1.0+local"

# Where the fetcher unpacks. Scarthgap has no UNPACKDIR and uses WORKDIR. Wrynose refuses
# an UNPACKDIR set to WORKDIR, so the recipe can't just default it.
TROWL_UNPACKDIR = "${@d.getVar('UNPACKDIR') or d.getVar('WORKDIR')}"
S = "${TROWL_UNPACKDIR}/trowl"
B = "${WORKDIR}/build"

# The source comes from the checkout the layer sits in (TROWL_REPO in layer.conf).
FILESEXTRAPATHS:prepend := "${TROWL_REPO}:"
SRC_URI = " \
    file://LICENSE;subdir=trowl \
    file://NOTICE;subdir=trowl \
    file://go.mod;subdir=trowl \
    file://go.sum;subdir=trowl \
    file://cmd;subdir=trowl \
    file://internal;subdir=trowl \
    file://ui/src;subdir=trowl \
    file://ui/index.html;subdir=trowl \
    file://ui/package.json;subdir=trowl \
    file://ui/tsconfig.json;subdir=trowl \
    file://ui/vite.config.ts;subdir=trowl \
    file://ui/package-lock.json;subdir=trowl \
"

# Trowl needs Go 1.26 and Scarthgap ships 1.22, while neither release ships Node.
# Both come pinned here like install.sh pins them, so one recipe builds on every release.
TROWL_GO_VERSION = "1.26.0"
TROWL_NODE_VERSION = "22.12.0"
TROWL_GOARCH = "${@{'x86_64': 'amd64', 'aarch64': 'arm64'}.get(d.getVar('BUILD_ARCH'), 'unsupported')}"
TROWL_NODEARCH = "${@{'x86_64': 'x64', 'aarch64': 'arm64'}.get(d.getVar('BUILD_ARCH'), 'unsupported')}"
SRC_URI += " \
    https://go.dev/dl/go${TROWL_GO_VERSION}.linux-${TROWL_GOARCH}.tar.gz;name=go-${TROWL_GOARCH};subdir=toolchain \
    https://nodejs.org/dist/v${TROWL_NODE_VERSION}/node-v${TROWL_NODE_VERSION}-linux-${TROWL_NODEARCH}.tar.xz;name=node-${TROWL_NODEARCH};subdir=toolchain \
"
SRC_URI[go-amd64.sha256sum] = "aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235"
SRC_URI[go-arm64.sha256sum] = "bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd"
SRC_URI[node-x64.sha256sum] = "22982235e1b71fa8850f82edd09cdae7e3f32df1764a9ec298c72d25ef2c164f"
SRC_URI[node-arm64.sha256sum] = "8cfd5a8b9afae5a2e0bd86b0148ca31d2589c0ea669c2d0b11c132e35d90ed68"

# The Go modules in go.sum as module@version:zip-sha256:mod-sha256. Only the go.mod of
# check.v1 is needed. Scarthgap has no gomod fetcher so the proxy files are fetched as is.
TROWL_GOPROXY ?= "https://proxy.golang.org"
TROWL_GOMODS = " \
    github.com/corefense-security/kcond@v0.0.0-20261111140041-3186c6389424:9b9bc42e66379085b9f40bb399d739a4ce00fc82f3949a3b760286f8db34d002:60b88684c252db2f79fe740e783d59e04e446f551fd5036547638ee1c48de27b \
    github.com/ulikunitz/xz@v0.5.12:0cba3268140e7c112c329b19ce3d4c8d4768a784fe0c80112bfa7bf43ace1a4a:393876046d63d90f35f21c1bb4651b0985e76d8f14a48a7279ff947b96956e7b \
    gopkg.in/yaml.v3@v3.0.1:aab8fbc4e6300ea08e6afe1caea18a21c90c79f489f52c53e2f20431f1a9a015:21579860a20306fcf43b1bd234d1fba319499c77611b71c05f9bf3ba90dab939 \
    gopkg.in/check.v1@v0.0.0-20161208181325-20d25e280405::5c306e0d633cd66a11b40e2e5fbbc6da42110db7d72ea3c1524ceb45ee40c33f \
"

# The dashboard's npm packages come from ui/package-lock.json, each checked against its
# sha512. Wrynose disables the npmsw fetcher, so the tarballs are fetched one by one.
# Packages for another OS or CPU are left out.
TROWL_NPM_CPU = "${@{'x86_64': 'x64', 'aarch64': 'arm64'}.get(d.getVar('BUILD_ARCH'), 'unsupported')}"

python () {
    import base64, json, os, re
    lock = os.path.join(d.getVar("TROWL_REPO"), "ui", "package-lock.json")
    bb.parse.mark_dependency(d, lock)
    with open(lock) as f:
        packages = json.load(f).get("packages", {})
    cpu = d.getVar("TROWL_NPM_CPU")
    unpack = []
    for i, (key, info) in enumerate(sorted(packages.items())):
        url, integrity = info.get("resolved"), info.get("integrity", "")
        if not key or not url or not integrity.startswith("sha512-"):
            continue
        if "linux" not in info.get("os", ["linux"]) or cpu not in info.get("cpu", [cpu]):
            continue
        name = "npm%d" % i
        local = "npm-" + re.sub(r"[^A-Za-z0-9.-]", "_", key[len("node_modules/"):]) + "-" + info.get("version", "") + ".tgz"
        d.appendVar("SRC_URI", " %s;name=%s;unpack=0;subdir=npm;downloadfilename=%s" % (url, name, local))
        d.setVarFlag("SRC_URI", name + ".sha512sum", base64.b64decode(integrity[7:]).hex())
        unpack.append("%s,%s" % (key, local))
    d.setVar("TROWL_NPM", " ".join(unpack))

    proxy = d.getVar("TROWL_GOPROXY")
    for i, entry in enumerate((d.getVar("TROWL_GOMODS") or "").split()):
        mod, zipsum, modsum = entry.split(":")
        path, ver = mod.split("@")
        local = path.replace("/", "_") + "-" + ver
        for ext, sha in (("zip", zipsum), ("mod", modsum)):
            if not sha:
                continue
            name = "gomod%d%s" % (i, ext)
            d.appendVar("SRC_URI", " %s/%s/@v/%s.%s;name=%s;unpack=0;subdir=gomod;downloadfilename=%s.%s"
                        % (proxy, path, ver, ext, name, local, ext))
            d.setVarFlag("SRC_URI", name + ".sha256sum", sha)
}

TROWL_NODEDIR = "${TROWL_UNPACKDIR}/toolchain/node-v${TROWL_NODE_VERSION}-linux-${TROWL_NODEARCH}"
TROWL_GODIR = "${TROWL_UNPACKDIR}/toolchain/go"

# A local module proxy so go build needs no network. go.sum still checks every module.
do_configure() {
    proxy=${WORKDIR}/goproxy
    rm -rf $proxy
    for entry in ${TROWL_GOMODS}; do
        mod=${entry%%:*}
        path=${mod%@*}
        ver=${mod#*@}
        name=$(echo $path | tr / _)-$ver
        mkdir -p $proxy/$path/@v
        cp ${TROWL_UNPACKDIR}/gomod/$name.mod $proxy/$path/@v/$ver.mod
        if [ -e ${TROWL_UNPACKDIR}/gomod/$name.zip ]; then
            cp ${TROWL_UNPACKDIR}/gomod/$name.zip $proxy/$path/@v/$ver.zip
        fi
        echo "{\"Version\":\"$ver\"}" > $proxy/$path/@v/$ver.info
    done

    for entry in ${TROWL_NPM}; do
        dir=${S}/ui/${entry%%,*}
        rm -rf $dir
        mkdir -p $dir
        tar -xzf ${TROWL_UNPACKDIR}/npm/${entry#*,} -C $dir --strip-components=1 --no-same-owner
    done
}

do_compile() {
    # Nothing links node_modules/.bin so vite is run by path.
    cd ${S}/ui
    PATH="${TROWL_NODEDIR}/bin:$PATH" node node_modules/vite/bin/vite.js build

    cd ${S}
    mkdir -p ${B}
    PATH="${TROWL_GODIR}/bin:$PATH" GOWORK=off GOTOOLCHAIN=local GOPROXY=file://${WORKDIR}/goproxy \
        GOSUMDB=off GOFLAGS=-modcacherw GOCACHE=${B}/gocache GOPATH=${B}/gopath CGO_ENABLED=0 \
        go build -trimpath -o ${B}/trowl ./cmd/trowl
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/trowl ${D}${bindir}/trowl
}
