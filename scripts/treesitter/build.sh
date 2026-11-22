#!/usr/bin/env bash
# build.sh -- rebuild nox's embedded tree-sitter modules (ADR 0006, rule 1).
#
#   scripts/treesitter/build.sh           rebuild into core/treesitter/wasm/
#   scripts/treesitter/build.sh --check   rebuild into a temporary directory and
#                                         fail unless every module is byte-equal
#                                         to the committed one
#
# Every input is pinned in pins.json: the runtime and each grammar by commit,
# the compiler (wasi-sdk) by SHA-256, the build image by digest, the platform
# by name. Sources are fetched by commit and verified; compilation runs in the
# container only, so the host's compilers never touch the output. Requires
# git, jq, docker and sha256sum or shasum.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
pins="$here/pins.json"
out_dir="$repo_root/core/treesitter/wasm"
check=0
if [ "${1:-}" = "--check" ]; then
  check=1
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
src="$work/src"
build_out="$work/out"
mkdir -p "$src" "$build_out/licenses"

# fetch <dir> <repo> <commit>: the tree at exactly that commit, nothing else.
fetch() {
  local dir="$1" url="$2" commit="$3"
  git init -q "$dir"
  git -C "$dir" fetch -q --depth 1 "$url" "$commit"
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
  local got
  got="$(git -C "$dir" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    echo "build.sh: $url fetched $got, pinned $commit" >&2
    exit 1
  fi
}

fetch "$src/runtime" "$(jq -r .runtime.repo "$pins")" "$(jq -r .runtime.commit "$pins")"
cp "$src/runtime/LICENSE" "$build_out/licenses/tree-sitter.LICENSE"

modules="$(jq -r '.modules[].name' "$pins")"
for m in $modules; do
  fetch "$src/$m" "$(jq -r --arg m "$m" '.modules[] | select(.name == $m) | .repo' "$pins")" \
    "$(jq -r --arg m "$m" '.modules[] | select(.name == $m) | .commit' "$pins")"
  cp "$src/$m/LICENSE" "$build_out/licenses/tree-sitter-$m.LICENSE"
done
cp "$here/nox_ts.c" "$src/nox_ts.c"

platform="$(jq -r .toolchain.platform "$pins")"
image="nox-treesitter-build:$(cat "$here/Dockerfile" <(jq -c .toolchain "$pins") | sha256 | cut -c1-16)"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -q --platform "$platform" -t "$image" \
    --build-arg BASE_IMAGE="$(jq -r .toolchain.base_image "$pins")" \
    --build-arg WASI_SDK_URL="$(jq -r .toolchain.wasi_sdk_url "$pins")" \
    --build-arg WASI_SDK_SHA256="$(jq -r .toolchain.wasi_sdk_sha256 "$pins")" \
    "$here" >/dev/null
fi

for m in $modules; do
  # X("name", function) per language, and the grammar sources each needs.
  langs="$(jq -r --arg m "$m" '.modules[] | select(.name == $m) | .languages | map("X(\"\(.name)\", \(.function))") | join(" ")' "$pins")"
  dirs="$(jq -r --arg m "$m" '.modules[] | select(.name == $m) | .languages[].dir' "$pins")"
  # As the invoking user, so the mounted output is writable on a Linux host
  # (Docker Desktop maps ownership; a Linux runner does not).
  docker run --rm --platform "$platform" --network none --user "$(id -u):$(id -g)" \
    -v "$src:/src:ro" -v "$build_out:/out" \
    -e LANGS="$langs" -e DIRS="$dirs" -e MODULE="$m" \
    "$image" bash -euo pipefail -c '
      cc=/opt/wasi-sdk/bin/clang
      flags=(--target=wasm32-wasip1 -O2 -std=c11 -ffunction-sections -fdata-sections
             -ffile-prefix-map=/src/=./ -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE
             -I/src/runtime/lib/include -I/src/runtime/lib/src)
      objs=()
      mkdir -p /tmp/obj
      $cc "${flags[@]}" -c /src/runtime/lib/src/lib.c -o /tmp/obj/runtime.o
      objs+=(/tmp/obj/runtime.o)
      i=0
      for d in $DIRS; do
        g=/src/$MODULE/$d/src
        $cc "${flags[@]}" -I"$g" -c "$g/parser.c" -o /tmp/obj/parser$i.o
        objs+=(/tmp/obj/parser$i.o)
        if [ -f "$g/scanner.c" ]; then
          $cc "${flags[@]}" -I"$g" -c "$g/scanner.c" -o /tmp/obj/scanner$i.o
          objs+=(/tmp/obj/scanner$i.o)
        fi
        i=$((i + 1))
      done
      $cc "${flags[@]}" "-DNOX_LANGUAGES=$LANGS" -c /src/nox_ts.c -o /tmp/obj/nox_ts.o
      objs+=(/tmp/obj/nox_ts.o)
      $cc --target=wasm32-wasip1 -mexec-model=reactor -Wl,--gc-sections -Wl,--strip-all \
        "${objs[@]}" -o "/out/$MODULE.wasm"
    '
done

(cd "$build_out" && sha256 $(for m in $modules; do echo "$m.wasm"; done) > SHA256SUMS)

if [ "$check" = 1 ]; then
  # The sums file and every committed file, byte for byte: a module edited
  # without its sum, or a sum edited without its module, both fail.
  failed=0
  if ! diff -u "$out_dir/SHA256SUMS" "$build_out/SHA256SUMS"; then
    failed=1
  fi
  for f in $(cd "$build_out" && ls *.wasm licenses/*); do
    if ! cmp -s "$build_out/$f" "$out_dir/$f"; then
      echo "build.sh --check: core/treesitter/wasm/$f differs from what pins.json builds" >&2
      failed=1
    fi
  done
  if [ "$failed" = 1 ]; then
    echo "build.sh --check: the committed modules are not what pins.json builds" >&2
    exit 1
  fi
  echo "build.sh --check: every module and license rebuilt byte-equal"
  exit 0
fi

mkdir -p "$out_dir/licenses"
cp "$build_out"/*.wasm "$build_out/SHA256SUMS" "$out_dir/"
cp "$build_out"/licenses/* "$out_dir/licenses/"
cat "$out_dir/SHA256SUMS"
