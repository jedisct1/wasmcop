#include <stdint.h>

__attribute__((import_module("env"), import_name("device_id"))) uint32_t device_id(void);
__attribute__((import_module("env"), import_name("abort"))) void host_abort(void);

static uint8_t heap[4096];
static uint32_t heap_used;

__attribute__((export_name("my_alloc")))
uint8_t *my_alloc(uint32_t size)
{
    uint8_t *block = heap + heap_used;
    heap_used += size;
    return block;
}

// Refuses keys that didn't come from my_alloc.
__attribute__((export_name("seal")))
uint32_t seal(const uint8_t *key, uint32_t len)
{
    uintptr_t start = (uintptr_t)heap;
    if ((uintptr_t)key < start || (uintptr_t)key + len > start + sizeof heap) {
        host_abort();
    }
    uint32_t hash = device_id();
    for (uint32_t i = 0; i < len; i++) {
        hash = (hash ^ key[i]) * 16777619;
    }
    return hash;
}
