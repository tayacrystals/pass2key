/* Compares the packet and armor output for the checked-in end-to-end vector
   byte for byte. The seed, fingerprint and user ID are read from
   vectors/e2e-test-example.org.json, so the JSON stays the single source of
   truth and no constant is duplicated here.

   This test does not run Argon2 (which would take minutes and 4 GiB); it
   starts from the recorded seed. Argon2 itself is covered by --selftest and,
   for the production parameters, by `make check-slow`. */

#include "check.h"
#include "armor.h"
#include "buffer.h"
#include "openpgp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path)
{
    FILE *stream = fopen(path, "rb");
    char *data;
    long size;

    CHECK(stream != NULL);
    CHECK(fseek(stream, 0, SEEK_END) == 0);
    size = ftell(stream);
    CHECK(size > 0);
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
    data = (char *)malloc((size_t)size + 1);
    CHECK(data != NULL);
    CHECK(fread(data, 1, (size_t)size, stream) == (size_t)size);
    data[size] = '\0';
    fclose(stream);
    return data;
}

/* Extracts a string field from the vector JSON. Deliberately tiny: the file is
   written by hand and has a fixed shape. */
static void json_string(const char *json, const char *key, char *out,
                        size_t out_size)
{
    char pattern[64];
    const char *start;
    const char *end;
    size_t len;

    CHECK(snprintf(pattern, sizeof(pattern), "\"%s\": \"", key) > 0);
    start = strstr(json, pattern);
    CHECK(start != NULL);
    start += strlen(pattern);
    end = strchr(start, '"');
    CHECK(end != NULL);
    len = (size_t)(end - start);
    CHECK(len + 1 <= out_size);
    memcpy(out, start, len);
    out[len] = '\0';
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void hex_decode(const char *text, uint8_t *out, size_t out_len)
{
    size_t i;

    CHECK(strlen(text) == 2 * out_len);
    for (i = 0; i < out_len; i++) {
        int high = hex_digit(text[2 * i]);
        int low = hex_digit(text[2 * i + 1]);

        CHECK(high >= 0 && low >= 0);
        out[i] = (uint8_t)((high << 4) | low);
    }
}

static char *armor_to_string(const Buffer *packets, int public_only)
{
    FILE *stream = tmpfile();
    char *text;
    long size;

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

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "vectors";
    char json_path[512];
    char asc_path[512];
    char public_path[512];
    char seed_hex[128];
    char fingerprint_hex[128];
    char email[256];
    uint8_t seed[32];
    uint8_t expected_fingerprint[20];
    uint8_t fingerprint[20];
    char *json;
    char *expected_armor;
    char *expected_public;
    char *armor;
    Buffer packets = {0};

    CHECK(snprintf(json_path, sizeof(json_path), "%s/e2e-test-example.org.json",
                   dir) > 0);
    CHECK(snprintf(asc_path, sizeof(asc_path), "%s/e2e-test-example.org.asc",
                   dir) > 0);
    CHECK(snprintf(public_path, sizeof(public_path),
                   "%s/e2e-test-example.org.public.asc", dir) > 0);

    json = read_file(json_path);
    expected_armor = read_file(asc_path);
    expected_public = read_file(public_path);

    json_string(json, "seed", seed_hex, sizeof(seed_hex));
    json_string(json, "fingerprint", fingerprint_hex,
                sizeof(fingerprint_hex));
    json_string(json, "email", email, sizeof(email));
    hex_decode(seed_hex, seed, sizeof(seed));
    hex_decode(fingerprint_hex, expected_fingerprint,
               sizeof(expected_fingerprint));

    buffer_init(&packets);
    CHECK(openpgp_build(&packets, email, seed, 0, fingerprint) == 0);
    CHECK_MEMEQ(fingerprint, expected_fingerprint, sizeof(fingerprint));
    armor = armor_to_string(&packets, 0);
    CHECK(strcmp(armor, expected_armor) == 0);
    free(armor);
    buffer_free(&packets);

    buffer_init(&packets);
    CHECK(openpgp_build(&packets, email, seed, 1, fingerprint) == 0);
    CHECK_MEMEQ(fingerprint, expected_fingerprint, sizeof(fingerprint));
    armor = armor_to_string(&packets, 1);
    CHECK(strcmp(armor, expected_public) == 0);
    free(armor);
    buffer_free(&packets);

    free(json);
    free(expected_armor);
    free(expected_public);

    TEST_OK("test_e2e");
    return 0;
}
