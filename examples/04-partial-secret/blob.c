// A blob is 16 bytes of public salt, a 32-byte secret key, and 16 bytes of public label.

#include <stdint.h>

#define KEY_START 16
#define KEY_END 48

// Branching on the salt is fine, it's public.
__attribute__((export_name("digest")))
void digest(const uint8_t *blob, uint32_t *out)
{
    uint32_t rounds = (blob[0] & 3) + 1;
    uint32_t hash = 0x811c9dc5;
    for (uint32_t round = 0; round < rounds; round++) {
        for (uint32_t i = KEY_START; i < KEY_END; i++) {
            hash = (hash ^ blob[i]) * 16777619;
        }
    }
    *out = hash;
}

// Treats the key as a C string, so timing shows where its first zero byte is.
__attribute__((export_name("digest_as_string")))
void digest_as_string(const uint8_t *blob, uint32_t *out)
{
    uint32_t hash = 0x811c9dc5;
    for (uint32_t i = KEY_START; i < KEY_END && blob[i] != 0; i++) {
        hash = (hash ^ blob[i]) * 16777619;
    }
    *out = hash;
}
