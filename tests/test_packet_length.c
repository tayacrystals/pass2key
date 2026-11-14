#include "buffer.h"
#include "openpgp.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void check_user_id_header(size_t email_len, uint8_t first,
                                 uint8_t second, uint8_t length_of_length)
{
    uint8_t seed[32];
    uint8_t fingerprint[20];
    char *email = (char *)malloc(email_len + 1);
    Buffer packets = {0};
    size_t offset = 90;
    size_t i;

    assert(email != NULL);
    memset(email, 'a', email_len);
    email[email_len - 2] = '@';
    email[email_len - 1] = 'b';
    email[email_len] = '\0';

    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(i + 1);

    buffer_init(&packets);
    assert(openpgp_build(&packets, email, seed, 0, fingerprint) == 0);
    assert(packets.len > offset + length_of_length + email_len);

    assert(packets.data[offset] == 0xcd);
    assert(packets.data[offset + 1] == first);
    if (length_of_length == 3) {
        assert(packets.data[offset + 2] == second);
    } else if (length_of_length == 6) {
        assert(packets.data[offset + 2] == second);
        assert(((size_t)packets.data[offset + 2] << 24 |
                (size_t)packets.data[offset + 3] << 16 |
                (size_t)packets.data[offset + 4] << 8 |
                (size_t)packets.data[offset + 5]) == email_len);
    }
    assert(memcmp(packets.data + offset + length_of_length, email,
                  email_len) == 0);

    buffer_free(&packets);
    free(email);
}

int main(void)
{
    check_user_id_header(16, 16, 0, 2);
    check_user_id_header(200, (uint8_t)(((200 - 192) >> 8) + 192),
                         (uint8_t)(200 - 192), 3);
    check_user_id_header(9000, 0xff, 0, 6);
    return 0;
}
