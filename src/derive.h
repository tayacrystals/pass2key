#ifndef PASS2KEY_DERIVE_H
#define PASS2KEY_DERIVE_H

#include <stdint.h>

int derive_seed(uint8_t seed[32], const char *email,
                const char *passphrase);
int derive_selftest(void);

#endif
