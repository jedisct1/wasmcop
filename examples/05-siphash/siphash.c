// SipHash-2-4, with a one-shot and a streaming interface.

#include <stdint.h>

typedef struct {
    uint64_t v0, v1, v2, v3;
    uint8_t pending[8];
    uint32_t pending_len;
    uint32_t total_len;
} siphash_state;

static uint64_t load64(const uint8_t *p)
{
    uint64_t x;
    __builtin_memcpy(&x, p, sizeof x);
    return x;
}

static uint64_t rotl(uint64_t x, int bits)
{
    return (x << bits) | (x >> (64 - bits));
}

static void sip_round(siphash_state *s)
{
    s->v0 += s->v1;
    s->v1 = rotl(s->v1, 13) ^ s->v0;
    s->v0 = rotl(s->v0, 32);
    s->v2 += s->v3;
    s->v3 = rotl(s->v3, 16) ^ s->v2;
    s->v0 += s->v3;
    s->v3 = rotl(s->v3, 21) ^ s->v0;
    s->v2 += s->v1;
    s->v1 = rotl(s->v1, 17) ^ s->v2;
    s->v2 = rotl(s->v2, 32);
}

static void absorb(siphash_state *s, uint64_t block)
{
    s->v3 ^= block;
    sip_round(s);
    sip_round(s);
    s->v0 ^= block;
}

__attribute__((export_name("siphash_init")))
void siphash_init(siphash_state *s, const uint8_t key[16])
{
    uint64_t k0 = load64(key);
    uint64_t k1 = load64(key + 8);
    s->v0 = k0 ^ 0x736f6d6570736575;
    s->v1 = k1 ^ 0x646f72616e646f6d;
    s->v2 = k0 ^ 0x6c7967656e657261;
    s->v3 = k1 ^ 0x7465646279746573;
    s->pending_len = 0;
    s->total_len = 0;
}

__attribute__((export_name("siphash_update")))
void siphash_update(siphash_state *s, const uint8_t *message, uint32_t len)
{
    s->total_len += len;
    for (uint32_t i = 0; i < len; i++) {
        s->pending[s->pending_len++] = message[i];
        if (s->pending_len == sizeof s->pending) {
            absorb(s, load64(s->pending));
            s->pending_len = 0;
        }
    }
}

__attribute__((export_name("siphash_final")))
void siphash_final(siphash_state *s, uint8_t tag[8])
{
    uint64_t last = (uint64_t)s->total_len << 56;
    for (uint32_t i = 0; i < s->pending_len; i++) {
        last |= (uint64_t)s->pending[i] << (8 * i);
    }
    absorb(s, last);
    s->v2 ^= 0xff;
    for (int round = 0; round < 4; round++) {
        sip_round(s);
    }
    uint64_t result = s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
    __builtin_memcpy(tag, &result, sizeof result);
}

__attribute__((export_name("siphash")))
void siphash(uint8_t tag[8], const uint8_t *message, uint32_t len, const uint8_t key[16])
{
    siphash_state s;
    siphash_init(&s, key);
    siphash_update(&s, message, len);
    siphash_final(&s, tag);
}

__attribute__((export_name("siphash_verify")))
uint32_t siphash_verify(const uint8_t expected[8], const uint8_t received[8])
{
    uint32_t difference = 0;
    for (int i = 0; i < 8; i++) {
        difference |= expected[i] ^ received[i];
    }
    return (difference - 1) >> 31;
}

// Only hands over the message if its tag was right.
__attribute__((export_name("release_message")))
void release_message(uint32_t ok, uint8_t *out, const uint8_t *message, uint32_t len)
{
    if (ok) {
        for (uint32_t i = 0; i < len; i++) {
            out[i] = message[i];
        }
    }
}

// Fine for public data, but the lookups would leak a secret.
__attribute__((export_name("hex_encode")))
void hex_encode(char *out, const uint8_t *data, uint32_t len)
{
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < len; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
}
