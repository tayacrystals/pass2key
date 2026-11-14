#define _POSIX_C_SOURCE 200809L

#include "monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    unsigned long mib = argc > 1 ? strtoul(argv[1], NULL, 10) : 256;
    unsigned long passes = argc > 2 ? strtoul(argv[2], NULL, 10) : 10;
    unsigned long lanes = argc > 3 ? strtoul(argv[3], NULL, 10) : 1;
    uint8_t password[32];
    uint8_t salt[16];
    uint8_t output[32];
    void *work;
    size_t work_size = (size_t)mib * 1024 * 1024;
    struct timespec start;
    struct timespec end;
    double seconds;
    crypto_argon2_config config;
    crypto_argon2_inputs inputs;

    memset(password, 1, sizeof(password));
    memset(salt, 2, sizeof(salt));
    work = malloc(work_size);
    if (work == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = (uint32_t)(work_size / 1024);
    config.nb_passes = (uint32_t)passes;
    config.nb_lanes = (uint32_t)lanes;
    inputs.pass = password;
    inputs.salt = salt;
    inputs.pass_size = sizeof(password);
    inputs.salt_size = sizeof(salt);

    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_argon2(output, sizeof(output), work, config, inputs,
                  crypto_argon2_no_extras);
    clock_gettime(CLOCK_MONOTONIC, &end);

    seconds = (double)(end.tv_sec - start.tv_sec) +
              (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("%lu MiB, %lu passes, %lu lanes: %.3f s, %.2f GiB/s\n",
           mib, passes, lanes, seconds,
           (double)mib * (double)passes / 1024.0 / seconds);
    free(work);
    return 0;
}
