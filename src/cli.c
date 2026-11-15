#include "cli.h"

int cli_parse_hex_fingerprint(const char *text,
                              uint8_t fingerprint[PASS2KEY_FINGERPRINT_LEN])
{
    size_t digits = 0;
    const char *p;

    if (text == NULL)
        return -1;

    for (p = text; *p != '\0'; p++) {
        int value = 0;
        char c = *p;

        if (c == ' ')
            continue;
        if (c >= '0' && c <= '9')
            value = c - '0';
        else if (c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            return -1;

        if (digits >= 2 * PASS2KEY_FINGERPRINT_LEN)
            return -1;
        if (digits % 2 == 0)
            fingerprint[digits / 2] = (uint8_t)(value << 4);
        else
            fingerprint[digits / 2] |= (uint8_t)value;
        digits++;
    }

    return digits == 2 * PASS2KEY_FINGERPRINT_LEN ? 0 : -1;
}
