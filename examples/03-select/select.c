#include <stdint.h>

// Looks constant-time, but clang turns it into a wasm `select`.
// Singlepass compiles that to a branch.
__attribute__((export_name("choose_masked")))
uint32_t choose_masked(uint32_t bit, uint32_t a, uint32_t b)
{
    uint32_t mask = 0 - (bit & 1);
    return (a & mask) | (b & ~mask);
}

// Same code, but the empty asm stops clang from seeing through the mask.
__attribute__((export_name("choose_opaque")))
uint32_t choose_opaque(uint32_t bit, uint32_t a, uint32_t b)
{
    uint32_t mask = 0 - (bit & 1);
    __asm__("" : "+r"(mask));
    return (a & mask) | (b & ~mask);
}
