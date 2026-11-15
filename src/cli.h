#ifndef PASS2KEY_CLI_H
#define PASS2KEY_CLI_H

#include <stddef.h>
#include <stdint.h>

#define PASS2KEY_FINGERPRINT_LEN 20

/* Parses 40 hexadecimal digits. Spaces are ignored, letters may be upper or
   lower case; any other character, or a digit count other than 40, is
   rejected. Returns 0 on success and -1 on any error. */
int cli_parse_hex_fingerprint(const char *text,
                              uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN]);

#endif
