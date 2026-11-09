#include <stdint.h>

#define WASI(name) __attribute__((import_module("wasi_snapshot_preview1"), import_name(name)))

typedef struct {
    const void *data;
    uint32_t len;
} ciovec;

WASI("random_get") int32_t random_get(void *buffer, uint32_t len);
WASI("args_get") int32_t args_get(char **argv, char *text);
WASI("environ_get") int32_t environ_get(char **environ, char *text);
WASI("fd_write") int32_t fd_write(int32_t fd, const ciovec *iovs, uint32_t count, uint32_t *written);

// How many attempts this takes depends on the key.
__attribute__((export_name("keygen_retry")))
void keygen_retry(uint8_t *key, uint32_t len)
{
    do {
        random_get(key, len);
    } while (key[0] == 0);
}

__attribute__((export_name("keygen")))
void keygen(uint8_t *key, uint32_t len)
{
    random_get(key, len);
}

// A leftover debug print.
__attribute__((export_name("print_key")))
void print_key(const uint8_t *key, uint32_t len)
{
    ciovec iov = { key, len };
    uint32_t written;
    fd_write(2, &iov, 1, &written);
}

static char *pointers[16];
static char text[1024];

__attribute__((export_name("key_size_from_args")))
void key_size_from_args(uint32_t *size)
{
    args_get(pointers, text);
    uint32_t value = 0;
    for (const char *p = pointers[1]; *p; p++) {
        value = value * 10 + (uint32_t)(*p - '0');
    }
    *size = value;
}

__attribute__((export_name("first_env_var")))
void first_env_var(char *out, uint32_t len)
{
    environ_get(pointers, text);
    for (uint32_t i = 0; i < len; i++) {
        out[i] = pointers[0][i];
    }
}
