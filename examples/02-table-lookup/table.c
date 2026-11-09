#include <stdint.h>

// The 4-bit S-box of the PRESENT block cipher.
static const uint8_t SBOX[16] = { 0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2 };

// Stops the compiler from turning the masks in sbox_ct into branches.
// Example 03 shows what happens without it.
static inline uint32_t opaque(uint32_t x)
{
    __asm__("" : "+r"(x));
    return x;
}

// Which memory gets read depends on the secret.
__attribute__((export_name("sbox_leaky")))
uint32_t sbox_leaky(uint32_t x)
{
    return SBOX[x & 15];
}

// Reads the whole table every time.
__attribute__((export_name("sbox_ct")))
uint32_t sbox_ct(uint32_t x)
{
    uint32_t result = 0;
    for (uint32_t i = 0; i < 16; i++) {
        uint32_t is_match = opaque(((i ^ (x & 15)) - 1) >> 31);
        result |= SBOX[i] & (0 - is_match);
    }
    return result;
}

// Only the key goes through the table.
__attribute__((export_name("encrypt")))
void encrypt(uint8_t *out, const uint8_t *message, const uint8_t *key)
{
    for (uint32_t i = 0; i < 8; i++) {
        out[i] = message[i] ^ SBOX[key[i] & 15];
    }
}
