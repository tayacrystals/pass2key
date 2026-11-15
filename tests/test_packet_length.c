#include "check.h"
#include "buffer.h"
#include "openpgp.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Returns the total length (header included) of the first packet, which must
   be the secret-key packet. Used instead of a hardcoded offset so a change to
   the key packet cannot silently shift the user ID packet. */
static size_t first_packet_length(const Buffer *packets)
{
    uint8_t first;

    CHECK(packets->len > 2);
    CHECK((packets->data[0] & 0xc0) == 0xc0);
    CHECK((packets->data[0] & 0x3f) == 5);

    first = packets->data[1];
    if (first < 192)
        return 2 + (size_t)first;
    if (first < 224)
        return 3 + ((((size_t)first - 192) << 8) + packets->data[2] + 192);

    CHECK(first == 255);
    return 6 + ((size_t)packets->data[2] << 24 |
                (size_t)packets->data[3] << 16 |
                (size_t)packets->data[4] << 8 |
                (size_t)packets->data[5]);
}

static void check_user_id_header(size_t email_len, uint8_t first,
                                 uint8_t second, size_t length_of_length)
{
    uint8_t seed[32];
    uint8_t fingerprint[20];
    char *email = (char *)malloc(email_len + 1);
    Buffer packets = {0};
    size_t offset;
    size_t i;

    CHECK(email != NULL);
    memset(email, 'a', email_len);
    email[email_len - 2] = '@';
    email[email_len - 1] = 'b';
    email[email_len] = '\0';

    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(i + 1);

    buffer_init(&packets);
    CHECK(openpgp_build(&packets, email, seed, 0, fingerprint) == 0);
    offset = first_packet_length(&packets);
    CHECK(packets.len > offset + length_of_length + email_len);

    CHECK(packets.data[offset] == 0xcd);
    CHECK(packets.data[offset + 1] == first);
    if (length_of_length == 3)
        CHECK(packets.data[offset + 2] == second);
    if (length_of_length == 6) {
        size_t encoded = (size_t)packets.data[offset + 2] << 24 |
                         (size_t)packets.data[offset + 3] << 16 |
                         (size_t)packets.data[offset + 4] << 8 |
                         (size_t)packets.data[offset + 5];
        CHECK(packets.data[offset + 2] == second);
        CHECK(encoded == email_len);
    }
    CHECK(memcmp(packets.data + offset + length_of_length, email, email_len) ==
          0);

    buffer_free(&packets);
    free(email);
}

static void check_packet_length_class(size_t len, uint8_t first, uint8_t second,
                                     size_t length_of_length)
{
    check_user_id_header(len, first, second, length_of_length);
}

int main(void)
{
    /* One value per length class. */
    check_packet_length_class(16, 16, 0, 2);
    check_packet_length_class(200, (uint8_t)(((200 - 192) >> 8) + 192),
                              (uint8_t)(200 - 192), 3);
    check_packet_length_class(9000, 0xff, 0, 6);

    /* The switch points of RFC 4880 section 4.2.2: 191/192 and 8383/8384. */
    check_packet_length_class(191, 191, 0, 2);
    check_packet_length_class(192, 192, 0, 3);
    check_packet_length_class(8383, 223, 255, 3);
    check_packet_length_class(8384, 0xff, 0, 6);

    TEST_OK("test_packet_length");
    return 0;
}
