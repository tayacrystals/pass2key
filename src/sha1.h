#ifndef PASS2KEY_SHA1_H
#define PASS2KEY_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[5];
    uint64_t total;
    uint8_t block[64];
    size_t used;
} Sha1Ctx;

void sha1_init(Sha1Ctx *ctx);
void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(Sha1Ctx *ctx, uint8_t digest[20]);
void sha1(uint8_t digest[20], const void *data, size_t len);

#endif
