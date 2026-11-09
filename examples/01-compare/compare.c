// Comparing a secret tag with one that came from the network.

#include <stdint.h>

// Stops at the first difference, so timing shows how many bytes were right.
__attribute__((export_name("compare_leaky")))
int compare_leaky(const uint8_t *tag, const uint8_t *given, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (tag[i] != given[i]) {
            return 0;
        }
    }
    return 1;
}

// Always looks at every byte, so timing gives nothing away.
__attribute__((export_name("compare_ct")))
int compare_ct(const uint8_t *tag, const uint8_t *given, uint32_t len)
{
    uint32_t difference = 0;
    for (uint32_t i = 0; i < len; i++) {
        difference |= tag[i] ^ given[i];
    }
    return (difference - 1) >> 31;
}
