SUMMARY = "llama.cpp's llama-server, which Trowl runs to write its Overview summary"
HOMEPAGE = "https://github.com/ggml-org/llama.cpp"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=223b26b3c1143120c87e2b13111d3e99"

inherit cmake native

# The same release and options as install.sh and the Dockerfile. The v0.8.0 tag.
SRC_URI = "git://github.com/ggml-org/llama.cpp.git;protocol=https;nobranch=1;destsuffix=llama.cpp"
SRCREV = "8642541b255bfb5dc39cd351a178be09013a55d6"
BB_GIT_SHALLOW = "1"

# Scarthgap has no UNPACKDIR and uses WORKDIR.
S = "${@d.getVar('UNPACKDIR') or d.getVar('WORKDIR')}/llama.cpp"

# Trowl talks to the server over plain HTTP on localhost. Without LLAMA_OPENSSL=OFF it links
# the native sysroot's OpenSSL and then can't start outside it.
# GGML_NATIVE=OFF alone builds for baseline x86-64 with no AVX, which runs many times slower.
# Native builds are shared through sstate so they can't be tuned to this host either. Every CPU
# variant is built as a backend instead and llama-server loads the best one at runtime, like
# llama.cpp's own releases.
EXTRA_OECMAKE = "-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DGGML_NATIVE=OFF \
    -DGGML_BACKEND_DL=ON -DGGML_CPU_ALL_VARIANTS=ON \
    -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_OPENSSL=OFF"

# llama-server loads the CPU backends from its own directory. The other libraries go in libdir.
do_install() {
    install -d ${D}${bindir} ${D}${libdir}
    install -m 0755 ${B}/bin/llama-server ${D}${bindir}/
    for lib in ${B}/bin/lib*.so*; do
        case $(basename $lib) in
        libggml-cpu-*) cp -P $lib ${D}${bindir}/ ;;
        *) cp -P $lib ${D}${libdir}/ ;;
        esac
    done
}
