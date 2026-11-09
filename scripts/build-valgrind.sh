#!/bin/sh
# Builds a Valgrind that also reports division and square root on secrets, and installs it in your cache directory, where Wasmcop finds it.
# This uses the system C compiler, because zig cc can't link Valgrind's tools at the fixed address they need.
set -eu

version=3.26.0
sha256=8d54c717029106f1644aadaf802ab9692e53d93dd015cbd19e74190eba616bd7

root=$(cd "$(dirname "$0")/.." && pwd)
prefix=${XDG_CACHE_HOME:-$HOME/.cache}/wasmcop/valgrind
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cd "$work"
curl -fsSL -o valgrind.tar.bz2 "https://sourceware.org/pub/valgrind/valgrind-$version.tar.bz2"
echo "$sha256  valgrind.tar.bz2" | sha256sum -c -
tar xjf valgrind.tar.bz2
cd "valgrind-$version"

patch -p1 < "$root/valgrind/varlat-20250805.patch"
./configure --prefix="$prefix"
make -j"$(nproc)"
make install

echo "Installed in $prefix"
