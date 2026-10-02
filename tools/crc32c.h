/*
 * crc32c.h — CRC32C (Castagnoli, reflected polynomial 0x82F63B78) for the
 * user-space tools, shared by mkfs_mxfs and chk_mxfs.
 *
 * crc32c(crc, data, len) is the raw update: no inversion on entry or exit, so
 * callers keep passing ~0U and inverting exactly as before.
 *
 * WHY.  Both tools carried a byte-at-a-time table CRC, about 250 MB/s.  A
 * format and a check each CRC every page of the TCP authority ledger (264 MiB
 * at 128 GiB), so that loop was 1.04 s of a 1.64 s format.  On x86-64 the SSE4.2
 * crc32 instruction computes the same update at several GB/s; it is used when
 * the CPU has it (checked once at run time) and the table otherwise, so the
 * tools still build and run on any CPU.
 */
#ifndef MXFS_TOOLS_CRC32C_H
#define MXFS_TOOLS_CRC32C_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint32_t crc32c_table[256];
static bool crc32c_initialized;

static void crc32c_init(void)
{
    uint32_t i, j, crc;

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78;
            else
                crc >>= 1;
        }
        crc32c_table[i] = crc;
    }
    crc32c_initialized = true;
}

static uint32_t crc32c_soft(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t i;

    if (!crc32c_initialized)
        crc32c_init();
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ p[i]) & 0xFF];
    return crc;
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
__attribute__((target("sse4.2")))
static uint32_t crc32c_hw(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = data;
    uint64_t c = crc;

    while (len >= 8) {
        uint64_t v;

        memcpy(&v, p, sizeof(v));
        c = __builtin_ia32_crc32di(c, v);
        p += 8;
        len -= 8;
    }
    while (len--)
        c = __builtin_ia32_crc32qi((uint32_t)c, *p++);
    return (uint32_t)c;
}

static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
    static int have_hw = -1;

    if (have_hw < 0)
        have_hw = __builtin_cpu_supports("sse4.2") ? 1 : 0;
    return have_hw ? crc32c_hw(crc, data, len) : crc32c_soft(crc, data, len);
}
#else
static uint32_t crc32c(uint32_t crc, const void *data, size_t len)
{
    return crc32c_soft(crc, data, len);
}
#endif

#endif /* MXFS_TOOLS_CRC32C_H */
