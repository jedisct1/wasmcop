// On many CPUs, division takes more or less time depending on the values.

#include <stdint.h>

#define Q 3329

// Same shape as the KyberSlash bug in ML-KEM: a secret divided by a constant.
__attribute__((export_name("compress_div")))
uint32_t compress_div(uint32_t coefficient)
{
    return (((coefficient << 1) + Q / 2) / Q) & 1;
}

// The fix from the reference code.
// For coefficients below q, it gives the same result as compress_div.
__attribute__((export_name("compress_mul")))
uint32_t compress_mul(uint32_t coefficient)
{
    uint32_t t = (coefficient << 1) + 1665;
    t *= 80635;
    t >>= 28;
    return t & 1;
}

// The low bit keeps the divisor from being zero, which would trap.
__attribute__((export_name("reduce")))
uint32_t reduce(uint32_t value, uint32_t modulus)
{
    return value % (modulus | 1);
}
