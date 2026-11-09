int leak(const unsigned char *p) {
    if (p[0]) {
        return 7;
    }
    return 9;
}

/* The .wasm next to this file was built with Zig 0.18: zig cc -target wasm32-freestanding -O0 -g -fno-sanitize=undefined -nostdlib -fdebug-prefix-map=$PWD=. -Wl,--no-entry -Wl,--export=leak -o tests/fixtures/dwarf.wasm tests/fixtures/dwarf.c */
