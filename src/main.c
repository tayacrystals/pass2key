#define _POSIX_C_SOURCE 200809L

#include "armor.h"
#include "buffer.h"
#include "cli.h"
#include "derive.h"
#include "input.h"
#include "monocypher.h"
#include "openpgp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif
#if defined(__linux__)
#include <sys/prctl.h>
#endif

typedef struct {
    const char *email;
    const char *expected;
    int expected_set;
    int public_only;
    int selftest;
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
            "  -h, --help            show this help\n"
            "\n"
            "If standard input is not a terminal the passphrase is read from it\n"
            "without a prompt; otherwise it is prompted for with echo disabled.\n"
            "\n"
            "Exit status: 0 success, 2 usage error, 1 any other failure\n"
            "(including a fingerprint mismatch and an invalid passphrase).\n");
}

/* A core dump, a ptrace attach or swap-out during the several-minute
   derivation would expose the passphrase and the derived private key. Core
   dumps are disabled for the whole process; the 4 GiB work area is not
   locked and can still be swapped, which is documented in the README. */
static void harden_process(void)
{
#if defined(__unix__) || defined(__APPLE__)
    struct rlimit limit;

    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    (void)setrlimit(RLIMIT_CORE, &limit);
#endif
#if defined(__linux__)
    (void)prctl(PR_SET_DUMPABLE, 0);
#endif
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
    int i;

    harden_process();

    /* --help wins over any other argument, including a malformed one, but not
       over an explicit end-of-options marker. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0)
            break;
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        }
    }

    if (parse_options(argc, argv, &options) != 0) {
        usage(stderr);
        return 2;
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
        cli_parse_hex_fingerprint(options.expected, expected) != 0) {
        fprintf(stderr,
                "pass2key: --expect requires 40 hexadecimal digits (spaces allowed)\n");
        usage(stderr);
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
        else if (read_status == -5)
            fprintf(stderr,
                    "pass2key: cannot disable terminal echo; refusing to read the passphrase\n");
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
        /* +1 covers the terminating NUL, which normalize_passphrase allocates. */
        crypto_wipe(passphrase, strlen(passphrase) + 1);
        free(passphrase);
    }
    crypto_wipe(seed, sizeof(seed));
    free(email);
    crypto_wipe(expected, sizeof(expected));
    crypto_wipe(fingerprint, sizeof(fingerprint));
    return status;
}
