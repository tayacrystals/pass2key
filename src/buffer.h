#ifndef PASS2KEY_BUFFER_H
#define PASS2KEY_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    int failed;
} Buffer;

void buffer_init(Buffer *buf);
void buffer_free(Buffer *buf);
int buffer_reserve(Buffer *buf, size_t extra);
int buffer_append(Buffer *buf, const void *data, size_t len);
int buffer_byte(Buffer *buf, uint8_t value);
int buffer_u16be(Buffer *buf, uint16_t value);
int buffer_u32be(Buffer *buf, uint32_t value);
int buffer_mpi(Buffer *buf, const uint8_t *data, size_t len);

#endif
