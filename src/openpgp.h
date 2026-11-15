#ifndef PASS2KEY_OPENPGP_H
#define PASS2KEY_OPENPGP_H

#include "buffer.h"

#include <stdint.h>

#define PASS2KEY_FINGERPRINT_LEN 20

/* seed is the RFC 8032 private key. It is treated as read-only: the caller
   keeps ownership and must wipe it itself. fingerprint receives the 20-byte
   v4 fingerprint (SHA-1) of the public key. */
int openpgp_build(Buffer *output, const char *email, const uint8_t seed[32],
                  int public_only,
                  uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN]);

#endif
