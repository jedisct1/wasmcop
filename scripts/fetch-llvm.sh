#!/bin/sh
# Downloads wasmer's prebuilt LLVM, for systems without LLVM 22 packages.
# On Ubuntu, installing llvm-22-dev and libpolly-22-dev is simpler.
set -eu

prefix=${XDG_CACHE_HOME:-$HOME/.cache}/wasmcop/llvm-22
mkdir -p "$prefix"
curl -fsSL https://github.com/wasmerio/llvm-custom-builds/releases/download/22.x/llvm-linux-amd64.tar.zst | tar --zstd -xf - -C "$prefix"

echo "Now build with: LLVM_SYS_221_PREFIX=$prefix make"
