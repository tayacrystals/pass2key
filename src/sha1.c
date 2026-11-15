#include "sha1.h"

#include <string.h>

static uint32_t rol32(uint32_t value, unsigned int shift)
{
    /* shift is never 0 in this file; keep the definition safe anyway so a
       future call site cannot introduce a shift by 32 (undefined). */
    if (shift == 0)
        return value;
    return (value << shift) | (value >> (32 - shift));
}

static void sha1_compress(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    unsigned int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f;
        uint32_t k;
        uint32_t tmp;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        tmp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_init(Sha1Ctx *ctx)
{
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->total = 0;
    ctx->used = 0;
}

void sha1_update(Sha1Ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->total += len;

    while (len != 0) {
        size_t room = sizeof(ctx->block) - ctx->used;
        size_t take = len < room ? len : room;

        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;

        if (ctx->used == sizeof(ctx->block)) {
            sha1_compress(ctx->state, ctx->block);
            ctx->used = 0;
        }
    }
}

void sha1_final(Sha1Ctx *ctx, uint8_t digest[20])
{
    uint64_t bits = ctx->total * 8;
    unsigned int i;

    ctx->block[ctx->used++] = 0x80;
    if (ctx->used > 56) {
        memset(ctx->block + ctx->used, 0, sizeof(ctx->block) - ctx->used);
        sha1_compress(ctx->state, ctx->block);
        ctx->used = 0;
    }
    memset(ctx->block + ctx->used, 0, 56 - ctx->used);

    for (i = 0; i < 8; i++)
        ctx->block[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    sha1_compress(ctx->state, ctx->block);

    for (i = 0; i < 5; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

void sha1(uint8_t digest[20], const void *data, size_t len)
{
    Sha1Ctx ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)data, len);
    sha1_final(&ctx, digest);
}
