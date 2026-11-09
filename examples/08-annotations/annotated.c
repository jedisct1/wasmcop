#include <stdint.h>

// In a real project, only test builds would have these imports.
#define WASMCOP(name) __attribute__((import_module("wasmcop"), import_name(name)))

WASMCOP("poison") void wasmcop_poison(const void *data, uint32_t len);
WASMCOP("assert_public") void wasmcop_assert_public(const void *data, uint32_t len);
WASMCOP("declassify_i32") uint32_t wasmcop_declassify_i32(uint32_t value);

#define Q 3329

// Keeps the first 12-bit value below Q, or returns Q if there isn't one.
// Leaks how many values it threw away.
__attribute__((export_name("sample")))
uint32_t sample(const uint8_t *stream, uint32_t len)
{
    for (uint32_t i = 0; i + 2 <= len; i += 2) {
        uint32_t candidate = (stream[i] | (uint32_t)stream[i + 1] << 8) & 0xfff;
        if (candidate < Q) {
            return candidate;
        }
    }
    return Q;
}

// If the values are independent and uniform, throwing one away says nothing about the one that's kept.
// So that decision can be public.
__attribute__((export_name("sample_declassified")))
uint32_t sample_declassified(const uint8_t *stream, uint32_t len)
{
    for (uint32_t i = 0; i + 2 <= len; i += 2) {
        uint32_t candidate = (stream[i] | (uint32_t)stream[i + 1] << 8) & 0xfff;
        if (wasmcop_declassify_i32(candidate < Q)) {
            return candidate;
        }
    }
    return Q;
}

static uint8_t device_key[16] = { 0x13, 0x37, 0xc0, 0xde };

// A test can't reach this key, so the module marks it secret itself.
__attribute__((export_name("device_key_fingerprint")))
uint32_t device_key_fingerprint(void)
{
    static const char digits[] = "0123456789abcdef";
    wasmcop_poison(device_key, sizeof device_key);
    return digits[device_key[0] >> 4];
}

// This is about to leave the module, so it can't be secret.
__attribute__((export_name("send_packet")))
void send_packet(const uint8_t *packet, uint32_t len)
{
    wasmcop_assert_public(packet, len);
}
