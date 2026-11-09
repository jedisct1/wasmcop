// Nothing's wrong with these functions, the tests in broken.toml are the problem.

#include <stdint.h>

__attribute__((export_name("mac")))
uint32_t mac(const uint8_t *key, uint32_t len)
{
    if (len != 32) {
        return 0;
    }
    uint32_t tag = 0;
    for (uint32_t i = 0; i < len; i++) {
        tag = (tag ^ key[i]) * 16777619;
    }
    return tag;
}

__attribute__((export_name("increment")))
void increment(uint8_t *out, const uint8_t *in)
{
    *out = *in + 1;
}

__attribute__((export_name("read_at")))
uint32_t read_at(const uint8_t *data, uint32_t len, uint32_t index)
{
    if (index >= len) {
        __builtin_trap();
    }
    return data[index];
}
