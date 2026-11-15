#ifndef PASS2KEY_TESTS_CHECK_H
#define PASS2KEY_TESTS_CHECK_H

#include <stdio.h>
#include <stdlib.h>

/* Deliberately not assert(): assertions disappear under -DNDEBUG, which is a
   common packaging and CI flag, and a silently vacuous test is worse than no
   test. CHECK always fails loudly and always exits non-zero. */
#define CHECK(condition)                                                      \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,   \
                    #condition);                                              \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

#define CHECK_MEMEQ(got, want, len)                                           \
    do {                                                                      \
        if (memcmp((got), (want), (len)) != 0) {                              \
            fprintf(stderr, "%s:%d: byte mismatch: %s != %s\n", __FILE__,      \
                    __LINE__, #got, #want);                                   \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

#define TEST_OK(name) (fprintf(stderr, "%s: ok\n", (name)))

#endif
