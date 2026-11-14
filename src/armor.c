#include "armor.h"

#include <string.h>

static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint32_t crc24(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xb704ceu;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i] << 16;
        for (bit = 0; bit < 8; bit++) {
            crc <<= 1;
            if (crc & 0x1000000u) {
                crc &= 0xffffffu;
                crc ^= 0x864cfbu;
            }
        }
    }
    return crc & 0xffffffu;
}

static int write_base64_line(FILE *stream, const uint8_t *data, size_t len)
{
    char line[65];
    size_t out = 0;

    while (len != 0) {
        size_t take = len >= 3 ? 3 : len;
        uint32_t value = (uint32_t)data[0] << 16;

        if (take > 1)
            value |= (uint32_t)data[1] << 8;
        if (take > 2)
            value |= (uint32_t)data[2];

        line[out++] = base64_alphabet[(value >> 18) & 0x3f];
        line[out++] = base64_alphabet[(value >> 12) & 0x3f];
        if (take > 1)
            line[out++] = base64_alphabet[(value >> 6) & 0x3f];
        else
            line[out++] = '=';
        if (take > 2)
            line[out++] = base64_alphabet[value & 0x3f];
        else
            line[out++] = '=';

        data += take;
        len -= take;

        if (out == 64 || len == 0) {
            line[out] = '\0';
            if (fprintf(stream, "%s\n", line) < 0)
                return -1;
            out = 0;
        }
    }
    return 0;
}

static int write_crc24(FILE *stream, uint32_t crc)
{
    char line[6];
    int i;

    line[0] = '=';
    for (i = 0; i < 4; i++)
        line[i + 1] = base64_alphabet[(crc >> (18 - i * 6)) & 0x3f];
    line[5] = '\0';
    return fprintf(stream, "%s\n", line) < 0 ? -1 : 0;
}

int armor_write(FILE *stream, const uint8_t *data, size_t len,
                int public_key)
{
    const char *begin = public_key
        ? "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        : "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
    const char *end = public_key
        ? "-----END PGP PUBLIC KEY BLOCK-----\n"
        : "-----END PGP PRIVATE KEY BLOCK-----\n";

    if (fputs(begin, stream) == EOF)
        return -1;
    if (fputc('\n', stream) == EOF)
        return -1;
    if (write_base64_line(stream, data, len) != 0)
        return -1;
    if (write_crc24(stream, crc24(data, len)) != 0)
        return -1;
    if (fputs(end, stream) == EOF)
        return -1;
    return fflush(stream) == 0 ? 0 : -1;
}
