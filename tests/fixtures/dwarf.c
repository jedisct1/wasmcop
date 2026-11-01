int leak(const unsigned char *p) {
    if (p[0]) {
        return 7;
    }
    return 9;
}

/* The .wasm next to this file was built with clang 21: clang --target=wasm32 -O0 -g -nostdlib -fdebug-prefix-map=$PWD=. -Wl,--no-entry -Wl,--export=leak -o tests/fixtures/dwarf.wasm tests/fixtures/dwarf.c */
