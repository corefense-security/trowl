# syntax=docker/dockerfile:1

# --- UI: build the single-file report viewer ---------------------------------
FROM node:22.11.0-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
# vite writes ../internal/report/ui/index.html, which the Go build embeds.
RUN mkdir -p ../internal/report/ui && npm run build

# --- trowl: one static binary with the UI and kernel baseline embedded ----
FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=ui /src/internal/report/ui/index.html ./internal/report/ui/index.html
ARG TROWL_VERSION=""
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/corefense-security/trowl/internal/model.version=${TROWL_VERSION}" \
      -o /out/trowl ./cmd/trowl

# --- llama.cpp server for the local model (CPU), pinned to a release tag -------
FROM debian:bookworm-slim AS llama
ARG LLAMA_CPP_TAG=v0.8.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${LLAMA_CPP_TAG}" https://github.com/ggml-org/llama.cpp.git /llama \
 && cmake -S /llama -B /llama/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
      -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
 && cmake --build /llama/build --target llama-server -j"$(nproc)"

# --- Runtime -----------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends e2fsprogs squashfs-tools sqlite3 zstd ca-certificates libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/trowl /usr/local/bin/trowl
# The model itself is not in the image: it is downloaded into /cache on the first scan.
COPY --from=llama /llama/build/bin/llama-server /usr/local/bin/llama-server
COPY --from=llama /llama/LICENSE /usr/share/doc/llama.cpp/LICENSE

RUN useradd --create-home --uid 10001 trowl && mkdir /cache && chown trowl /cache
USER trowl
WORKDIR /work
# The model, KEV, EPSS and link results are cached here; mount a volume to reuse them across
# runs (otherwise each run downloads the ~2.5 GB model again).
ENV TROWL_HOST=0.0.0.0 XDG_CACHE_HOME=/cache
VOLUME ["/cache"]
EXPOSE 8765
ENTRYPOINT ["trowl"]
CMD ["--help"]
