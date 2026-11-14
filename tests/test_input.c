#include "input.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void test_email(void)
{
    char *out = NULL;

    assert(normalize_email("  User@Example.ORG\t", &out) == 0);
    assert(strcmp(out, "user@example.org") == 0);
    free(out);
    out = NULL;

    assert(normalize_email("a@b", &out) == 0);
    assert(strcmp(out, "a@b") == 0);
    free(out);
    out = NULL;

    assert(normalize_email("", &out) != 0);
    assert(normalize_email("@example.org", &out) != 0);
    assert(normalize_email("user@", &out) != 0);
    assert(normalize_email("a@@b", &out) != 0);
    assert(normalize_email("a@b c", &out) == 0);
    free(out);
    out = NULL;
    assert(normalize_email("a\tb@example.org", &out) != 0);
    assert(normalize_email("a\x80@example.org", &out) != 0);
}

static void test_passphrase(void)
{
    static const unsigned char good[] =
        "  Correct\t HORSE   battery staple  ";
    static const unsigned char short_pass[] = "three word phrase";
    static const unsigned char tab_words[] = "one\ttwo\tthree\tfour";
    static const unsigned char bad[] = "one two three f\x80ur";
    char *out = NULL;

    assert(normalize_passphrase(good, sizeof(good) - 1, &out) == 0);
    assert(strcmp(out, "correct horse battery staple") == 0);
    free(out);
    out = NULL;

    assert(normalize_passphrase(tab_words, sizeof(tab_words) - 1, &out) == 0);
    assert(strcmp(out, "one two three four") == 0);
    free(out);
    out = NULL;

    assert(normalize_passphrase(short_pass, sizeof(short_pass) - 1, &out) != 0);
    assert(normalize_passphrase(bad, sizeof(bad) - 1, &out) != 0);
    assert(normalize_passphrase((const unsigned char *)"", 0, &out) != 0);
}

int main(void)
{
    test_email();
    test_passphrase();
    return 0;
}
