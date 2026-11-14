#include "armor.h"
#include "buffer.h"
#include "monocypher.h"
#include "openpgp.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t seed[32];
    uint8_t fingerprint[20];
    Buffer out = {0};
    size_t i;
    int public_only = argc > 1 && strcmp(argv[1], "public") == 0;

    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (uint8_t)(i + 1);
    buffer_init(&out);
    if (openpgp_build(&out, "test@example.org", seed, public_only,
                      fingerprint) != 0)
        return 1;
    for (i = 0; i < sizeof(fingerprint); i++)
        fprintf(stderr, "%02X", fingerprint[i]);
    fputc('\n', stderr);
    if (armor_write(stdout, out.data, out.len, public_only) != 0)
        return 1;
    if (out.data != NULL)
        crypto_wipe(out.data, out.cap);
    buffer_free(&out);
    return 0;
}
