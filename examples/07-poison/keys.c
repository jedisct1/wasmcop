#include <stdint.h>

// Stands in for a real key derivation.
__attribute__((export_name("derive_key")))
void derive_key(uint8_t key[16], const uint8_t salt[16])
{
    uint32_t hash = 0x811c9dc5;
    for (int i = 0; i < 16; i++) {
        hash = (hash ^ salt[i]) * 16777619;
        key[i] = hash >> 24;
    }
}

__attribute__((export_name("key_checksum")))
uint32_t key_checksum(const uint8_t key[16])
{
    uint32_t checksum = 0;
    for (int i = 0; i < 16; i++) {
        checksum ^= key[i];
    }
    return checksum;
}

__attribute__((export_name("key_is_all_zeros")))
uint32_t key_is_all_zeros(const uint8_t key[16])
{
    for (int i = 0; i < 16; i++) {
        if (key[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// The first four bytes of a key are a public id.
__attribute__((export_name("key_id_is_known")))
uint32_t key_id_is_known(const uint8_t key[16])
{
    for (int i = 0; i < 4; i++) {
        if (key[i] == 0xff) {
            return 0;
        }
    }
    return 1;
}
