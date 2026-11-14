#include "derive.h"

#include "sha1.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGON_MEMORY_KIB   UINT32_C(4194304)
#define ARGON_PASSES       UINT32_C(100)
#define ARGON_LANES        UINT32_C(1)
#define ARGON_BLOCK_BYTES  UINT32_C(1024)

static const uint8_t salt_prefix[9] = {
    'p', 'a', 's', 's', '2', 'k', 'e', 'y', 0x00
};

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    size_t i;

    fprintf(stderr, "%s", label);
    for (i = 0; i < len; i++)
        fprintf(stderr, "%02x", data[i]);
    fputc('\n', stderr);
}

static int argon_selftest(void)
{
    uint8_t password[32];
    uint8_t salt[16];
    uint8_t secret[8];
    uint8_t ad[12];
    uint8_t expected[32] = {
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
        0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
        0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
        0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
    };
    uint8_t output[32];
    void *work_area;
    crypto_argon2_config config;
    crypto_argon2_inputs inputs;
    crypto_argon2_extras extras;
    int result;

    memset(password, 0x01, sizeof(password));
    memset(salt, 0x02, sizeof(salt));
    memset(secret, 0x03, sizeof(secret));
    memset(ad, 0x04, sizeof(ad));

    work_area = malloc(32 * 1024);
    if (work_area == NULL) {
        fprintf(stderr, "selftest: cannot allocate Argon2 work area\n");
        return -1;
    }

    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = 32;
    config.nb_passes = 3;
    config.nb_lanes = 4;
    inputs.pass = password;
    inputs.salt = salt;
    inputs.pass_size = sizeof(password);
    inputs.salt_size = sizeof(salt);
    extras.key = secret;
    extras.ad = ad;
    extras.key_size = sizeof(secret);
    extras.ad_size = sizeof(ad);

    crypto_argon2(output, sizeof(output), work_area, config, inputs, extras);
    result = memcmp(output, expected, sizeof(expected)) == 0 ? 0 : -1;
    if (result != 0) {
        fprintf(stderr, "selftest: Argon2id RFC 9106 vector failed\n");
        print_hex("  got:      ", output, sizeof(output));
        print_hex("  expected: ", expected, sizeof(expected));
    }
    crypto_wipe(work_area, 32 * 1024);
    free(work_area);
    return result;
}

static int ed25519_selftest(void)
{
    uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    uint8_t expected_public[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };
    uint8_t expected_signature[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
    };
    uint8_t secret_key[64];
    uint8_t public_key[32];
    uint8_t signature[64];
    int result = 0;

    crypto_ed25519_key_pair(secret_key, public_key, seed);
    crypto_ed25519_sign(signature, secret_key, NULL, 0);
    if (memcmp(public_key, expected_public, sizeof(public_key)) != 0) {
        fprintf(stderr, "selftest: Ed25519 RFC 8032 public key failed\n");
        result = -1;
    }
    if (memcmp(signature, expected_signature, sizeof(signature)) != 0) {
        fprintf(stderr, "selftest: Ed25519 RFC 8032 signature failed\n");
        result = -1;
    }
    if (crypto_ed25519_check(signature, public_key, NULL, 0) != 0) {
        fprintf(stderr, "selftest: Ed25519 signature verification failed\n");
        result = -1;
    }
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(signature, sizeof(signature));
    return result;
}

static int sha1_selftest(void)
{
    static const uint8_t expected[20] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
    };
    uint8_t digest[20];

    sha1(digest, "abc", 3);
    if (memcmp(digest, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "selftest: SHA-1 vector failed\n");
        return -1;
    }
    return 0;
}

int derive_selftest(void)
{
    if (sha1_selftest() != 0)
        return -1;
    if (ed25519_selftest() != 0)
        return -1;
    if (argon_selftest() != 0)
        return -1;
    return 0;
}

int derive_seed(uint8_t seed[32], const char *email,
                const char *passphrase)
{
    size_t email_len = strlen(email);
    size_t password_len = strlen(passphrase);
    size_t salt_len;
    uint8_t *salt;
    void *work_area;
    size_t work_size;
    crypto_argon2_config config;
    crypto_argon2_inputs inputs;

    if (email_len > UINT32_MAX - sizeof(salt_prefix) ||
        password_len > UINT32_MAX) {
        fprintf(stderr, "pass2key: input is too long\n");
        return -1;
    }
    if (sizeof(size_t) < 8) {
        fprintf(stderr, "pass2key: a 64-bit system is required\n");
        return -1;
    }

    salt_len = sizeof(salt_prefix) + email_len;
    salt = (uint8_t *)malloc(salt_len);
    if (salt == NULL) {
        fprintf(stderr, "pass2key: cannot allocate salt\n");
        return -1;
    }
    memcpy(salt, salt_prefix, sizeof(salt_prefix));
    memcpy(salt + sizeof(salt_prefix), email, email_len);

    work_size = (size_t)ARGON_MEMORY_KIB * (size_t)ARGON_BLOCK_BYTES;
    work_area = malloc(work_size);
    if (work_area == NULL) {
        fprintf(stderr, "pass2key: cannot allocate %u MiB of Argon2 memory\n",
                ARGON_MEMORY_KIB / 1024);
        crypto_wipe(salt, salt_len);
        free(salt);
        return -1;
    }

    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = ARGON_MEMORY_KIB;
    config.nb_passes = ARGON_PASSES;
    config.nb_lanes = ARGON_LANES;
    inputs.pass = (const uint8_t *)passphrase;
    inputs.salt = salt;
    inputs.pass_size = (uint32_t)password_len;
    inputs.salt_size = (uint32_t)salt_len;

    crypto_argon2(seed, 32, work_area, config, inputs,
                  crypto_argon2_no_extras);

    crypto_wipe(work_area, work_size);
    free(work_area);
    crypto_wipe(salt, salt_len);
    free(salt);
    return 0;
}
