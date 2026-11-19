SUMMARY = "The model Trowl runs to write its Overview summary"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

inherit native

# Only do_fetch runs. The scan reads the model from DL_DIR so the large file isn't copied.
# TROWL_LLM_MODEL and TROWL_LLM_MODELS are in layer.conf.
python () {
    name = d.getVar("TROWL_LLM_MODEL")
    entry = d.getVarFlag("TROWL_LLM_MODELS", name)
    if not entry:
        raise bb.parse.SkipRecipe("TROWL_LLM_MODEL %s isn't in TROWL_LLM_MODELS" % name)
    file, url, sha = entry.split()
    d.setVar("SRC_URI", "%s;downloadfilename=%s;unpack=0" % (url, file))
    d.setVarFlag("SRC_URI", "sha256sum", sha)
}
