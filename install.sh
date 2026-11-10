#!/usr/bin/env bash
# Install Trowl on Debian or Ubuntu (x86-64 or arm64).
#
#   curl -fsSL https://raw.githubusercontent.com/corefense-security/trowl/main/install.sh | bash
#
# With llama-server for the Key summary (builds llama.cpp, so it takes a while):
#
#   curl -fsSL https://raw.githubusercontent.com/corefense-security/trowl/main/install.sh | bash -s -- --with-llm
#
# Go and Node are downloaded into a temporary directory for the build and removed afterwards.
set -euo pipefail

GO_VERSION=1.26.0 # at least go.mod's go line: GOTOOLCHAIN=local below won't fetch a newer one
GO_SHA_amd64=aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235
GO_SHA_arm64=bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd
NODE_VERSION=22.12.0
NODE_SHA_x64=22982235e1b71fa8850f82edd09cdae7e3f32df1764a9ec298c72d25ef2c164f
NODE_SHA_arm64=8cfd5a8b9afae5a2e0bd86b0148ca31d2589c0ea669c2d0b11c132e35d90ed68
LLAMA_CPP_TAG=v0.8.0 # keep in step with the Dockerfile
REPO=https://github.com/corefense-security/trowl.git

prefix=/usr/local
ref=main
source_dir=""
with_llm=0

usage() {
	cat <<USAGE
Usage: install.sh [options]

  --with-llm    also install llama-server for the Key summary; trowl scan downloads the
                model (--model) on first use
  --prefix DIR  install under DIR/bin (default: /usr/local)
  --ref REF     git branch or tag to build (default: main)
  --source DIR  build from a local checkout instead of cloning
  -h, --help    show this help
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
	--with-llm) with_llm=1 ;;
	--prefix) prefix="${2:?--prefix needs a directory}"; shift ;;
	--ref) ref="${2:?--ref needs a branch or tag}"; shift ;;
	--source) source_dir="${2:?--source needs a directory}"; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "install.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\n==> %s\n' "$*"; }
die() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "only Linux is supported"
command -v apt-get >/dev/null || die "needs apt-get (Debian or Ubuntu); for other systems use the Docker image"
case "$(uname -m)" in
x86_64) go_arch=amd64 node_arch=x64 ;;
aarch64 | arm64) go_arch=arm64 node_arch=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

sudo=""
if [ "$(id -u)" -ne 0 ]; then
	command -v sudo >/dev/null || die "run as root, or install sudo"
	sudo=sudo
fi

packages=(ca-certificates curl git xz-utils e2fsprogs squashfs-tools zstd sqlite3)
[ "$with_llm" = 1 ] && packages+=(build-essential cmake libgomp1)
say "Installing system packages"
$sudo apt-get update -qq
$sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${packages[@]}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 destination
	curl -fsSL "$1" -o "$3"
	echo "$2  $3" | sha256sum -c --quiet - || die "checksum mismatch for $1"
}

say "Downloading Go $GO_VERSION and Node $NODE_VERSION for the build"
go_sha="GO_SHA_$go_arch"
node_sha="NODE_SHA_$node_arch"
fetch "https://go.dev/dl/go$GO_VERSION.linux-$go_arch.tar.gz" "${!go_sha}" "$work/go.tar.gz"
fetch "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$node_arch.tar.xz" "${!node_sha}" "$work/node.tar.xz"
mkdir -p "$work/node"
tar -C "$work" -xzf "$work/go.tar.gz"
tar -C "$work/node" --strip-components=1 -xJf "$work/node.tar.xz"
export PATH="$work/go/bin:$work/node/bin:$PATH" GOPATH="$work/gopath" GOCACHE="$work/gocache" GOTOOLCHAIN=local GOFLAGS=-modcacherw
export npm_config_cache="$work/npm"

src="$work/trowl"
if [ -n "$source_dir" ]; then
	cp -r "$source_dir" "$src"
	rm -rf "$src/ui/node_modules"
else
	say "Fetching Trowl ($ref)"
	git clone -q --depth 1 --branch "$ref" "$REPO" "$src"
fi

say "Building the dashboard"
(cd "$src/ui" && npm ci --silent && npm run build --silent)

say "Building Trowl"
# kcond comes from the module proxy at the version go.mod pins. GOWORK=off ignores a developer's
# go.work that a --source checkout may carry, which points at a ../kcond this copy doesn't have.
(cd "$src" && GOWORK=off go build -o "$work/trowl-bin" ./cmd/trowl)

bindir="$prefix/bin"
$sudo mkdir -p "$bindir"
$sudo install -m 0755 "$work/trowl-bin" "$bindir/trowl"
# The licenses of what the binary includes (kcond, MIT), which must ship with it.
docdir="$prefix/share/doc/trowl"
$sudo mkdir -p "$docdir"
$sudo install -m 0644 "$src/LICENSE" "$src/THIRD_PARTY_NOTICES.md" "$docdir/"
# Debian keeps debugfs in /usr/sbin, which isn't on a normal user's PATH.
[ -e "$bindir/debugfs" ] || $sudo ln -s "$(PATH=$PATH:/usr/sbin:/sbin command -v debugfs)" "$bindir/debugfs"

if [ "$with_llm" = 1 ]; then
	say "Building llama-server $LLAMA_CPP_TAG (this takes a while)"
	git clone -q --depth 1 --branch "$LLAMA_CPP_TAG" https://github.com/ggml-org/llama.cpp.git "$work/llama"
	cmake -S "$work/llama" -B "$work/llama/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
		-DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF >/dev/null
	cmake --build "$work/llama/build" --target llama-server -j"$(nproc)" >/dev/null
	$sudo install -m 0755 "$work/llama/build/bin/llama-server" "$bindir/llama-server"
fi

say "Installed $("$bindir/trowl" --version) to $bindir/trowl"
case ":$PATH:" in
*":$bindir:"*) ;;
*) echo "Add $bindir to your PATH to run it by name." ;;
esac
echo "Try: trowl scan <image> -o report && trowl view report"
