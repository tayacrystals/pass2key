#ifndef PASS2KEY_ARMOR_H
#define PASS2KEY_ARMOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int armor_write(FILE *stream, const uint8_t *data, size_t len,
                int public_key);

#endif
