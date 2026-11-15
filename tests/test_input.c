#include "check.h"
#include "cli.h"
#include "input.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void test_email(void)
{
    char *out = NULL;

    CHECK(normalize_email("  User@Example.ORG\t", &out) == 0);
    CHECK(strcmp(out, "user@example.org") == 0);
    free(out);
    out = NULL;

    CHECK(normalize_email("a@b", &out) == 0);
    CHECK(strcmp(out, "a@b") == 0);
    free(out);
    out = NULL;

    CHECK(normalize_email("", &out) != 0);
    CHECK(normalize_email("@example.org", &out) != 0);
    CHECK(normalize_email("user@", &out) != 0);
    CHECK(normalize_email("a@@b", &out) != 0);
    /* Interior whitespace is preserved verbatim: no trimming or collapsing. */
    CHECK(normalize_email("a@b c", &out) == 0);
    CHECK(strcmp(out, "a@b c") == 0);
    free(out);
    out = NULL;
    /* A tab is filler only at the ends of the email, never inside it. */
    CHECK(normalize_email("\t a@b \t", &out) == 0);
    CHECK(strcmp(out, "a@b") == 0);
    free(out);
    out = NULL;
    CHECK(normalize_email("a\tb@example.org", &out) != 0);
    CHECK(normalize_email("a\x80@example.org", &out) != 0);
    CHECK(normalize_email("a\x7f@example.org", &out) != 0);
}

static void test_passphrase(void)
{
    static const unsigned char good[] =
        "  Correct\t HORSE   battery staple  ";
    static const unsigned char short_pass[] = "three word phrase";
    static const unsigned char tab_words[] = "one\ttwo\tthree\tfour";
    static const unsigned char bad[] = "one two three f\x80ur";
    char *out = NULL;

    CHECK(normalize_passphrase(good, sizeof(good) - 1, &out) == 0);
    CHECK(strcmp(out, "correct horse battery staple") == 0);
    free(out);
    out = NULL;

    CHECK(normalize_passphrase(tab_words, sizeof(tab_words) - 1, &out) == 0);
    CHECK(strcmp(out, "one two three four") == 0);
    free(out);
    out = NULL;

    CHECK(normalize_passphrase(short_pass, sizeof(short_pass) - 1, &out) != 0);
    CHECK(normalize_passphrase(bad, sizeof(bad) - 1, &out) != 0);
    CHECK(normalize_passphrase((const unsigned char *)"", 0, &out) != 0);
    CHECK(normalize_passphrase((const unsigned char *)"\t\t  \t", 5, &out) != 0);
    CHECK(normalize_passphrase((const unsigned char *)"one two\x01 three four",
                               19, &out) != 0);
}

static void test_fingerprint_parsing(void)
{
    uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN];
    static const uint8_t expected[PASS2KEY_FINGERPRINT_LEN] = {
        0x56, 0xf0, 0xdc, 0xe8, 0x65, 0x36, 0x61, 0xd1, 0xf0, 0x80,
        0x9d, 0x1c, 0x5a, 0x41, 0xa9, 0x6c, 0xe2, 0x32, 0xb7, 0xd6
    };

    CHECK(cli_parse_hex_fingerprint(
              "56F0DCE8653661D1F0809D1C5A41A96CE232B7D6", fingerprint) == 0);
    CHECK_MEMEQ(fingerprint, expected, sizeof(expected));

    CHECK(cli_parse_hex_fingerprint(
              "56f0dce8653661d1f0809d1c5a41a96ce232b7d6", fingerprint) == 0);
    CHECK_MEMEQ(fingerprint, expected, sizeof(expected));

    CHECK(cli_parse_hex_fingerprint(
              "56F0 DCE8 6536 61D1 F080 9D1C 5A41 A96C E232 B7D6",
              fingerprint) == 0);
    CHECK_MEMEQ(fingerprint, expected, sizeof(expected));

    /* 39 and 41 digits, wrong separators, prefixes and the empty string. */
    CHECK(cli_parse_hex_fingerprint(
              "56F0DCE8653661D1F0809D1C5A41A96CE232B7D", fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint(
              "56F0DCE8653661D1F0809D1C5A41A96CE232B7D6F", fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint(
              "56F0\tDCE8653661D1F0809D1C5A41A96CE232B7D6", fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint(
              "56F0-DCE8-6536-61D1-F080-9D1C-5A41-A96C-E232-B7D6",
              fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint(
              "0x56F0DCE8653661D1F0809D1C5A41A96CE232B7D6", fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint("", fingerprint) != 0);
    CHECK(cli_parse_hex_fingerprint(NULL, fingerprint) != 0);
}

int main(void)
{
    test_email();
    test_passphrase();
    test_fingerprint_parsing();
    TEST_OK("test_input");
    return 0;
}
