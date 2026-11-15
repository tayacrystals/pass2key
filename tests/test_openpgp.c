#include "check.h"
#include "armor.h"
#include "buffer.h"
#include "openpgp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINES 64

static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Same CRC-24 as RFC 4880 section 6.1, recomputed independently here so the
   armor writer is checked against a second implementation. */
static uint32_t crc24(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xb704ce;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i] << 16;
        for (bit = 0; bit < 8; bit++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= 0x1864cfb;
        }
    }
    return crc & 0xffffff;
}

static char *armor_to_string(const Buffer *packets, int public_only)
{
    char *text;
    FILE *stream;
    long size;

    stream = tmpfile();
    CHECK(stream != NULL);
    CHECK(armor_write(stream, packets->data, packets->len, public_only) == 0);
    CHECK(fflush(stream) == 0);
    CHECK(fseek(stream, 0, SEEK_END) == 0);
    size = ftell(stream);
    CHECK(size > 0);
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
    text = (char *)malloc((size_t)size + 1);
    CHECK(text != NULL);
    CHECK(fread(text, 1, (size_t)size, stream) == (size_t)size);
    text[size] = '\0';
    fclose(stream);
    return text;
}

/* Checks the armor framing, the 64-column wrapping and the CRC line against a
   separately computed CRC-24 of the packet bytes. */
static void check_armor(const Buffer *packets, int public_only)
{
    const char *begin = public_only
        ? "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        : "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n";
    const char *end = public_only
        ? "\n-----END PGP PUBLIC KEY BLOCK-----\n"
        : "\n-----END PGP PRIVATE KEY BLOCK-----\n";
    char *text = armor_to_string(packets, public_only);
    size_t len = strlen(text);
    size_t begin_len = strlen(begin);
    size_t end_len = strlen(end);
    size_t line_lengths[MAX_LINES];
    size_t line_count = 0;
    uint32_t crc = crc24(packets->data, packets->len);
    char expected_crc[6];
    const char *p;
    size_t i;

    CHECK(len > begin_len + end_len);
    CHECK(strncmp(text, begin, begin_len) == 0);
    CHECK(strcmp(text + len - end_len, end) == 0);

    p = text + begin_len;
    while (*p != '=') {
        const char *newline = strchr(p, '\n');
        size_t line_len;

        CHECK(newline != NULL);
        line_len = (size_t)(newline - p);
        CHECK(line_len > 0 && line_len <= 64);
        CHECK(line_count < MAX_LINES);
        line_lengths[line_count++] = line_len;
        p = newline + 1;
    }

    CHECK(line_count > 0);
    for (i = 0; i + 1 < line_count; i++)
        CHECK(line_lengths[i] == 64);

    expected_crc[0] = '=';
    for (i = 0; i < 4; i++)
        expected_crc[1 + i] =
            base64_alphabet[(crc >> (18 - (int)i * 6)) & 0x3f];
    expected_crc[5] = '\0';
    CHECK(strncmp(p, expected_crc, 5) == 0);
    CHECK(p[5] == '\n');
    CHECK(strcmp(p + 6, end + 1) == 0);

    free(text);
}

int main(void)
{
    /* Fingerprint of the public key derived from seed 01 02 ... 20. A change
       here means the byte-level encoding changed. */
    static const uint8_t expected_fingerprint[20] = {
        0x9c, 0x46, 0x56, 0x64, 0x0f, 0x04, 0x42, 0x9e, 0xe7, 0xa7,
        0x73, 0x06, 0x4d, 0x1c, 0x68, 0x66, 0x4a, 0x89, 0x00, 0xd7
    };
    uint8_t seed[32];
    uint8_t fingerprint[20];
    Buffer packets = {0};
    size_t i;

    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(i + 1);

    buffer_init(&packets);
    CHECK(openpgp_build(&packets, "test@example.org", seed, 0, fingerprint) ==
          0);
    CHECK_MEMEQ(fingerprint, expected_fingerprint, sizeof(fingerprint));
    check_armor(&packets, 0);
    buffer_free(&packets);

    buffer_init(&packets);
    CHECK(openpgp_build(&packets, "test@example.org", seed, 1, fingerprint) ==
          0);
    CHECK_MEMEQ(fingerprint, expected_fingerprint, sizeof(fingerprint));
    /* The public variant is the same key, UID and signature without the
       secret-key packet. */
    CHECK(packets.len > 0);
    CHECK(packets.data[0] == 0xc6); /* tag 6, public-key packet */
    check_armor(&packets, 1);
    buffer_free(&packets);

    TEST_OK("test_openpgp");
    return 0;
}
