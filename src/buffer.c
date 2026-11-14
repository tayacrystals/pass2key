#include "buffer.h"

#include "monocypher.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_INITIAL_CAPACITY 256

void buffer_init(Buffer *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
    buf->failed = 0;
}

void buffer_free(Buffer *buf)
{
    if (buf->data != NULL)
        crypto_wipe(buf->data, buf->cap);
    free(buf->data);
    buffer_init(buf);
}

int buffer_reserve(Buffer *buf, size_t extra)
{
    size_t needed;
    size_t capacity;
    uint8_t *data;

    if (buf->failed)
        return -1;
    if (extra > SIZE_MAX - buf->len) {
        buf->failed = 1;
        return -1;
    }

    needed = buf->len + extra;
    if (needed <= buf->cap)
        return 0;

    capacity = buf->cap == 0 ? BUFFER_INITIAL_CAPACITY : buf->cap;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }

    data = (uint8_t *)malloc(capacity);
    if (data == NULL) {
        buf->failed = 1;
        return -1;
    }
    if (buf->data != NULL) {
        memcpy(data, buf->data, buf->len);
        crypto_wipe(buf->data, buf->cap);
        free(buf->data);
    }

    buf->data = data;
    buf->cap = capacity;
    return 0;
}

int buffer_append(Buffer *buf, const void *data, size_t len)
{
    if (buffer_reserve(buf, len) != 0)
        return -1;
    if (len != 0)
        memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

int buffer_byte(Buffer *buf, uint8_t value)
{
    return buffer_append(buf, &value, 1);
}

int buffer_u16be(Buffer *buf, uint16_t value)
{
    uint8_t bytes[2];

    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
    return buffer_append(buf, bytes, sizeof(bytes));
}

int buffer_u32be(Buffer *buf, uint32_t value)
{
    uint8_t bytes[4];

    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
    return buffer_append(buf, bytes, sizeof(bytes));
}

int buffer_mpi(Buffer *buf, const uint8_t *data, size_t len)
{
    uint16_t bits;
    size_t first = 0;

    while (first < len && data[first] == 0)
        first++;

    if (first == len) {
        bits = 0;
    } else {
        size_t significant = len - first;
        int significant_bits = 0;
        uint8_t lead = data[first];

        while (lead != 0) {
            significant_bits++;
            lead = (uint8_t)(lead >> 1);
        }
        bits = (uint16_t)((significant - 1) * 8 + (size_t)significant_bits);
    }

    if (buffer_u16be(buf, bits) != 0)
        return -1;
    if (bits == 0)
        return 0;
    return buffer_append(buf, data + first, len - first);
}
