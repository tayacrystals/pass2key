#ifndef PASS2KEY_OPENPGP_H
#define PASS2KEY_OPENPGP_H

#include "buffer.h"

#include <stdint.h>

#define PASS2KEY_FINGERPRINT_LEN 20

int openpgp_build(Buffer *output, const char *email, uint8_t seed[32],
                  int public_only,
                  uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN]);

#endif
