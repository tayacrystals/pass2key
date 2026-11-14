#ifndef PASS2KEY_INPUT_H
#define PASS2KEY_INPUT_H

#include <stddef.h>

int normalize_email(const char *input, char **output);
int normalize_passphrase(const unsigned char *input, size_t input_len,
                         char **output);
int read_passphrase(unsigned char **output, size_t *output_len);

#endif
