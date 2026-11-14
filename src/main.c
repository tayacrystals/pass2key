#include "armor.h"
#include "buffer.h"
#include "derive.h"
#include "input.h"
#include "monocypher.h"
#include "openpgp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *email;
    const char *expected;
    int expected_set;
    int public_only;
    int selftest;
    int help;
} Options;

static void usage(FILE *stream)
{
    fprintf(stream,
            "Usage: pass2key [--public] [--expect FINGERPRINT] EMAIL\n"
            "       pass2key --selftest\n"
            "\n"
            "Derive a deterministic certify-only OpenPGP primary key from an\n"
            "email address and a passphrase. The passphrase is read from the\n"
            "terminal and is not echoed.\n"
            "\n"
            "  --public              output the public key only\n"
            "  --expect FINGERPRINT  fail without output unless the fingerprint matches\n"
            "  --selftest            run primitive self-tests\n"
            "  -h, --help            show this help\n");
}

static int parse_hex_fingerprint(const char *text,
                                 uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN])
{
    size_t digits = 0;
    const char *p;

    for (p = text; *p != '\0'; p++) {
        int value = 0;
        char c = *p;

        if (c == ' ')
            continue;
        if (c >= '0' && c <= '9')
            value = c - '0';
        else if (c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            return -1;

        if (digits >= 2 * PASS2KEY_FINGERPRINT_LEN)
            return -1;
        if (digits % 2 == 0)
            fingerprint[digits / 2] = (uint8_t)(value << 4);
        else
            fingerprint[digits / 2] |= (uint8_t)value;
        digits++;
    }

    return digits == 2 * PASS2KEY_FINGERPRINT_LEN ? 0 : -1;
}

static int parse_options(int argc, char **argv, Options *options)
{
    int i;
    int end_of_options = 0;

    memset(options, 0, sizeof(*options));

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (!end_of_options) {
            if (strcmp(arg, "--") == 0) {
                end_of_options = 1;
                continue;
            }
            if (strcmp(arg, "--public") == 0) {
                options->public_only = 1;
                continue;
            }
            if (strcmp(arg, "--selftest") == 0) {
                options->selftest = 1;
                continue;
            }
            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
                options->help = 1;
                continue;
            }
            if (strcmp(arg, "--expect") == 0) {
                if (options->expected_set || i + 1 >= argc) {
                    fprintf(stderr,
                            "pass2key: --expect needs exactly one fingerprint\n");
                    return -1;
                }
                options->expected = argv[++i];
                options->expected_set = 1;
                continue;
            }
            if (arg[0] == '-' && arg[1] != '\0') {
                fprintf(stderr, "pass2key: unknown option: %s\n", arg);
                return -1;
            }
        }

        if (options->email != NULL) {
            fprintf(stderr, "pass2key: exactly one email address is required\n");
            return -1;
        }
        options->email = arg;
    }

    return 0;
}

static void print_fingerprint(FILE *stream,
                              const uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN])
{
    size_t i;

    for (i = 0; i < PASS2KEY_FINGERPRINT_LEN; i++)
        fprintf(stream, "%02X", fingerprint[i]);
    fputc('\n', stream);
}

int main(int argc, char **argv)
{
    Options options;
    char *email = NULL;
    char *passphrase = NULL;
    unsigned char *raw_passphrase = NULL;
    size_t raw_passphrase_len = 0;
    uint8_t expected[PASS2KEY_FINGERPRINT_LEN];
    uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN];
    uint8_t seed[32];
    Buffer packets = {0};
    int status = 1;
    int read_status;

    if (parse_options(argc, argv, &options) != 0) {
        usage(stderr);
        return 2;
    }
    if (options.help) {
        usage(stdout);
        return 0;
    }
    if (options.selftest) {
        if (options.email != NULL || options.expected_set ||
            options.public_only) {
            fprintf(stderr,
                    "pass2key: --selftest cannot be combined with other arguments\n");
            return 2;
        }
        if (derive_selftest() != 0)
            return 1;
        printf("pass2key: selftest passed\n");
        return 0;
    }
    if (options.email == NULL) {
        usage(stderr);
        return 2;
    }
    if (options.expected_set &&
        parse_hex_fingerprint(options.expected, expected) != 0) {
        fprintf(stderr,
                "pass2key: --expect requires 40 hexadecimal digits (spaces allowed)\n");
        return 2;
    }

    if (normalize_email(options.email, &email) != 0) {
        fprintf(stderr,
                "pass2key: invalid email: use printable ASCII with exactly one '@'\n");
        return 2;
    }

    read_status = read_passphrase(&raw_passphrase, &raw_passphrase_len);
    if (read_status != 0) {
        if (read_status == -3)
            fprintf(stderr, "pass2key: no passphrase was provided\n");
        else if (read_status == -2)
            fprintf(stderr, "pass2key: cannot read the passphrase\n");
        else
            fprintf(stderr, "pass2key: cannot prompt for the passphrase\n");
        goto done;
    }

    if (normalize_passphrase(raw_passphrase, raw_passphrase_len,
                             &passphrase) != 0) {
        fprintf(stderr,
                "pass2key: invalid passphrase: use printable ASCII with at least four words\n");
        goto done;
    }

    fprintf(stderr, "Calculating your key, this takes several minutes...\n");
    fflush(stderr);

    if (derive_seed(seed, email, passphrase) != 0)
        goto done;
    if (openpgp_build(&packets, email, seed, options.public_only,
                      fingerprint) != 0) {
        fprintf(stderr, "pass2key: cannot encode the OpenPGP key\n");
        goto done;
    }

    if (options.expected_set &&
        memcmp(fingerprint, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "pass2key: fingerprint mismatch; no key written\n");
        fprintf(stderr, "  expected: ");
        print_fingerprint(stderr, expected);
        fprintf(stderr, "  derived:  ");
        print_fingerprint(stderr, fingerprint);
        fprintf(stderr,
                "pass2key: check the email and passphrase for a typo\n");
        goto done;
    }

    if (armor_write(stdout, packets.data, packets.len,
                    options.public_only) != 0) {
        fprintf(stderr, "pass2key: cannot write output\n");
        goto done;
    }

    status = 0;

done:
    if (packets.data != NULL)
        crypto_wipe(packets.data, packets.cap);
    buffer_free(&packets);
    if (raw_passphrase != NULL) {
        crypto_wipe(raw_passphrase, raw_passphrase_len + 1);
        free(raw_passphrase);
    }
    if (passphrase != NULL) {
        crypto_wipe(passphrase, strlen(passphrase));
        free(passphrase);
    }
    free(email);
    crypto_wipe(expected, sizeof(expected));
    crypto_wipe(fingerprint, sizeof(fingerprint));
    return status;
}
