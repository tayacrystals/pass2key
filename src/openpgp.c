#include "openpgp.h"

#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "sha1.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OPENPGP_VERSION_4 0x04
#define OPENPGP_ALG_EDDSA 0x16
#define OPENPGP_HASH_SHA512 0x0a
#define OPENPGP_SIG_POSITIVE 0x13

#define PACKET_SIGNATURE 2
#define PACKET_SECRET_KEY 5
#define PACKET_PUBLIC_KEY 6
#define PACKET_USER_ID 13

static const uint8_t ed25519_oid[9] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
};

static int append_packet(Buffer *output, uint8_t tag, const Buffer *body)
{
    uint8_t header[6];
    size_t header_len;
    size_t len = body->len;

    if (len <= 191) {
        header[0] = (uint8_t)(0xc0 | tag);
        header[1] = (uint8_t)len;
        header_len = 2;
    } else if (len <= 8383) {
        size_t adjusted = len - 192;

        header[0] = (uint8_t)(0xc0 | tag);
        header[1] = (uint8_t)((adjusted >> 8) + 192);
        header[2] = (uint8_t)adjusted;
        header_len = 3;
    } else {
        if (len > UINT32_MAX)
            return -1;
        header[0] = (uint8_t)(0xc0 | tag);
        header[1] = 0xff;
        header[2] = (uint8_t)(len >> 24);
        header[3] = (uint8_t)(len >> 16);
        header[4] = (uint8_t)(len >> 8);
        header[5] = (uint8_t)len;
        header_len = 6;
    }

    if (buffer_append(output, header, header_len) != 0)
        return -1;
    return buffer_append(output, body->data, body->len);
}

static int append_subpacket(Buffer *output, uint8_t type,
                            const void *data, size_t len)
{
    size_t sub_len = len + 1;
    uint8_t header[5];
    size_t header_len;

    if (sub_len <= 191) {
        header[0] = (uint8_t)sub_len;
        header_len = 1;
    } else if (sub_len <= 8383) {
        size_t adjusted = sub_len - 192;

        header[0] = (uint8_t)((adjusted >> 8) + 192);
        header[1] = (uint8_t)adjusted;
        header_len = 2;
    } else {
        if (sub_len > UINT32_MAX)
            return -1;
        header[0] = 0xff;
        header[1] = (uint8_t)(sub_len >> 24);
        header[2] = (uint8_t)(sub_len >> 16);
        header[3] = (uint8_t)(sub_len >> 8);
        header[4] = (uint8_t)sub_len;
        header_len = 5;
    }

    if (buffer_append(output, header, header_len) != 0)
        return -1;
    if (buffer_byte(output, type) != 0)
        return -1;
    return buffer_append(output, data, len);
}

static void sha512_update_u16(crypto_sha512_ctx *ctx, uint16_t value)
{
    uint8_t bytes[2];

    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
    crypto_sha512_update(ctx, bytes, sizeof(bytes));
}

static void sha512_update_u32(crypto_sha512_ctx *ctx, uint32_t value)
{
    uint8_t bytes[4];

    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
    crypto_sha512_update(ctx, bytes, sizeof(bytes));
}

static void sha512_update_key(crypto_sha512_ctx *ctx, const Buffer *key)
{
    uint8_t prefix = 0x99;

    crypto_sha512_update(ctx, &prefix, 1);
    sha512_update_u16(ctx, (uint16_t)key->len);
    crypto_sha512_update(ctx, key->data, key->len);
}

static int build_public_key(Buffer *key, const uint8_t public_key[32])
{
    uint8_t prefixed_public_key[33];

    if (buffer_byte(key, OPENPGP_VERSION_4) != 0)
        return -1;
    if (buffer_u32be(key, 0) != 0)
        return -1;
    if (buffer_byte(key, OPENPGP_ALG_EDDSA) != 0)
        return -1;
    if (buffer_byte(key, (uint8_t)sizeof(ed25519_oid)) != 0)
        return -1;
    if (buffer_append(key, ed25519_oid, sizeof(ed25519_oid)) != 0)
        return -1;

    prefixed_public_key[0] = 0x40;
    memcpy(prefixed_public_key + 1, public_key, 32);
    return buffer_mpi(key, prefixed_public_key,
                      sizeof(prefixed_public_key));
}

static int build_secret_key(Buffer *secret_key, const Buffer *public_key,
                            const uint8_t seed[32])
{
    Buffer mpi = {0};
    uint16_t checksum = 0;
    size_t i;
    int result = -1;

    buffer_init(&mpi);
    if (buffer_append(secret_key, public_key->data, public_key->len) != 0)
        goto done;
    if (buffer_byte(secret_key, 0x00) != 0)
        goto done;
    if (buffer_mpi(&mpi, seed, 32) != 0)
        goto done;
    for (i = 0; i < mpi.len; i++)
        checksum = (uint16_t)(checksum + mpi.data[i]);
    if (buffer_append(secret_key, mpi.data, mpi.len) != 0)
        goto done;
    if (buffer_u16be(secret_key, checksum) != 0)
        goto done;

    result = 0;
done:
    if (mpi.data != NULL)
        crypto_wipe(mpi.data, mpi.cap);
    buffer_free(&mpi);
    return result;
}

static int build_signature(Buffer *signature, const Buffer *public_key,
                           const char *email, size_t email_len,
                           const uint8_t fingerprint[20],
                           const uint8_t secret_key[64])
{
    Buffer hashed = {0};
    Buffer unhashed = {0};
    Buffer signature_body = {0};
    crypto_sha512_ctx ctx;
    uint8_t digest[64];
    uint8_t ed_signature[64];
    uint8_t issuer_fingerprint[21];
    uint8_t creation_time[4] = {0, 0, 0, 0};
    uint8_t key_flags = 0x01;
    uint8_t preferred_symmetric[2] = {0x09, 0x07};
    uint8_t preferred_hash[2] = {0x0a, 0x08};
    uint8_t preferred_compression = 0x00;
    uint8_t features = 0x01;
    int result = -1;

    buffer_init(&hashed);
    buffer_init(&unhashed);
    buffer_init(&signature_body);

    issuer_fingerprint[0] = OPENPGP_VERSION_4;
    memcpy(issuer_fingerprint + 1, fingerprint, 20);

    {
        struct {
            uint8_t type;
            const void *data;
            size_t len;
        } hashed_subpackets[] = {
            {33, issuer_fingerprint, sizeof(issuer_fingerprint)},
            {2, creation_time, sizeof(creation_time)},
            {27, &key_flags, sizeof(key_flags)},
            {11, preferred_symmetric, sizeof(preferred_symmetric)},
            {21, preferred_hash, sizeof(preferred_hash)},
            {22, &preferred_compression, sizeof(preferred_compression)},
            {30, &features, sizeof(features)},
        };
        size_t i;

        for (i = 0; i < sizeof(hashed_subpackets) / sizeof(hashed_subpackets[0]);
             i++) {
            if (append_subpacket(&hashed, hashed_subpackets[i].type,
                                 hashed_subpackets[i].data,
                                 hashed_subpackets[i].len) != 0)
                goto done;
        }
    }
    if (append_subpacket(&unhashed, 16, fingerprint + 12, 8) != 0)
        goto done;

    if (hashed.len > UINT16_MAX || unhashed.len > UINT16_MAX)
        goto done;

    if (buffer_byte(&signature_body, OPENPGP_VERSION_4) != 0)
        goto done;
    if (buffer_byte(&signature_body, OPENPGP_SIG_POSITIVE) != 0)
        goto done;
    if (buffer_byte(&signature_body, OPENPGP_ALG_EDDSA) != 0)
        goto done;
    if (buffer_byte(&signature_body, OPENPGP_HASH_SHA512) != 0)
        goto done;
    if (buffer_u16be(&signature_body, (uint16_t)hashed.len) != 0)
        goto done;
    if (buffer_append(&signature_body, hashed.data, hashed.len) != 0)
        goto done;

    crypto_sha512_init(&ctx);
    sha512_update_key(&ctx, public_key);
    {
        uint8_t user_id_marker = 0xb4;

        crypto_sha512_update(&ctx, &user_id_marker, 1);
        sha512_update_u32(&ctx, (uint32_t)email_len);
        crypto_sha512_update(&ctx, (const uint8_t *)email, email_len);
    }
    crypto_sha512_update(&ctx, signature_body.data, signature_body.len);
    {
        uint8_t trailer[6];

        trailer[0] = OPENPGP_VERSION_4;
        trailer[1] = 0xff;
        trailer[2] = (uint8_t)(signature_body.len >> 24);
        trailer[3] = (uint8_t)(signature_body.len >> 16);
        trailer[4] = (uint8_t)(signature_body.len >> 8);
        trailer[5] = (uint8_t)signature_body.len;
        crypto_sha512_update(&ctx, trailer, sizeof(trailer));
    }
    crypto_sha512_final(&ctx, digest);

    crypto_ed25519_sign(ed_signature, secret_key, digest, sizeof(digest));

    if (buffer_u16be(&signature_body, (uint16_t)unhashed.len) != 0)
        goto done;
    if (buffer_append(&signature_body, unhashed.data, unhashed.len) != 0)
        goto done;
    if (buffer_append(&signature_body, digest, 2) != 0)
        goto done;
    if (buffer_mpi(&signature_body, ed_signature, 32) != 0)
        goto done;
    if (buffer_mpi(&signature_body, ed_signature + 32, 32) != 0)
        goto done;

    if (buffer_append(signature, signature_body.data,
                      signature_body.len) != 0)
        goto done;

    result = 0;
done:
    buffer_free(&hashed);
    buffer_free(&unhashed);
    buffer_free(&signature_body);
    crypto_wipe(digest, sizeof(digest));
    crypto_wipe(ed_signature, sizeof(ed_signature));
    return result;
}

int openpgp_build(Buffer *output, const char *email, uint8_t seed[32],
                  int public_only,
                  uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN])
{
    Buffer public_key = {0};
    Buffer body = {0};
    uint8_t public_key_bytes[32];
    uint8_t key_seed[32];
    uint8_t signing_key[64];
    uint8_t fingerprint_input[3];
    size_t email_len = strlen(email);
    int result = -1;

    buffer_init(&public_key);
    buffer_init(&body);

    if (email_len > UINT32_MAX) {
        fprintf(stderr, "pass2key: email address is too long\n");
        goto done;
    }

    memcpy(key_seed, seed, sizeof(key_seed));
    crypto_ed25519_key_pair(signing_key, public_key_bytes, key_seed);

    if (build_public_key(&public_key, public_key_bytes) != 0)
        goto done;
    if (public_key.len > UINT16_MAX)
        goto done;

    fingerprint_input[0] = 0x99;
    fingerprint_input[1] = (uint8_t)(public_key.len >> 8);
    fingerprint_input[2] = (uint8_t)public_key.len;
    {
        Sha1Ctx ctx;

        sha1_init(&ctx);
        sha1_update(&ctx, fingerprint_input, sizeof(fingerprint_input));
        sha1_update(&ctx, public_key.data, public_key.len);
        sha1_final(&ctx, fingerprint);
    }

    if (public_only) {
        if (append_packet(output, PACKET_PUBLIC_KEY, &public_key) != 0)
            goto done;
    } else {
        if (build_secret_key(&body, &public_key, seed) != 0)
            goto done;
        if (append_packet(output, PACKET_SECRET_KEY, &body) != 0)
            goto done;
        if (body.data != NULL)
            crypto_wipe(body.data, body.cap);
        buffer_free(&body);
        buffer_init(&body);
    }

    if (buffer_append(&body, email, email_len) != 0)
        goto done;
    if (append_packet(output, PACKET_USER_ID, &body) != 0)
        goto done;
    buffer_free(&body);
    buffer_init(&body);

    if (build_signature(&body, &public_key, email, email_len, fingerprint,
                        signing_key) != 0)
        goto done;
    if (append_packet(output, PACKET_SIGNATURE, &body) != 0)
        goto done;

    result = 0;
done:
    crypto_wipe(seed, 32);
    crypto_wipe(signing_key, sizeof(signing_key));
    crypto_wipe(public_key_bytes, sizeof(public_key_bytes));
    buffer_free(&public_key);
    if (body.data != NULL)
        crypto_wipe(body.data, body.cap);
    buffer_free(&body);
    return result;
}
