#!/usr/bin/env python3
"""Extract the secret seed from a pass2key armored secret-key block.

Used to compare a freshly derived key against vectors/e2e-test-example.org.json.
Verifies the armor CRC-24 and the secret-key packet checksum, so a corrupted or
truncated file is reported instead of silently yielding a wrong seed.
"""

import base64
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def packet_length(data, offset):
    first = data[offset]
    if first < 192:
        return first, 1
    if first < 224:
        return ((first - 192) << 8) + data[offset + 1] + 192, 2
    if first == 255:
        return int.from_bytes(data[offset + 1:offset + 5], "big"), 5
    raise ValueError("unexpected packet length encoding")


def strip_armor(text):
    encoded = []
    crc_line = None
    in_body = False
    for line in text.splitlines():
        if line.startswith("-----BEGIN "):
            continue
        if line.startswith("-----END "):
            break
        if line == "":
            in_body = True
            continue
        if not in_body:
            raise ValueError("unexpected armor header line: %r" % line)
        if line.startswith("="):
            crc_line = line[1:]
            continue
        if crc_line is not None:
            raise ValueError("data after the armor CRC line")
        encoded.append(line)

    if crc_line is None:
        raise ValueError("missing armor CRC line")
    data = base64.b64decode("".join(encoded), validate=True)
    if len(crc_line) != 4:
        raise ValueError("malformed armor CRC line")
    expected = int.from_bytes(base64.b64decode(crc_line + "="), "big")
    if expected != crc24(data):
        raise ValueError(
            "armor CRC mismatch: file says %06x, data is %06x"
            % (expected, crc24(data))
        )
    return data


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: extract_seed.py <armored-secret-key-file>")

    with open(argv[1], "r", encoding="ascii") as stream:
        data = strip_armor(stream.read())

    if data[0] != 0xC5:
        raise ValueError("not an armored secret-key packet")

    body_len, header_len = packet_length(data, 1)
    body = data[1 + header_len:1 + header_len + body_len]
    if body[0] != 4 or body[5] != 22:
        raise ValueError("unexpected key version or algorithm")

    oid_len = body[6]
    offset = 7 + oid_len
    public_bits = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + (public_bits + 7) // 8
    if body[offset] != 0:
        raise ValueError("secret key is unexpectedly protected")
    offset += 1

    seed_bits = int.from_bytes(body[offset:offset + 2], "big")
    seed_len = (seed_bits + 7) // 8
    seed = body[offset + 2:offset + 2 + seed_len]

    checksum_at = offset + 2 + seed_len
    stored = int.from_bytes(body[checksum_at:checksum_at + 2], "big")
    computed = sum(body[offset:checksum_at]) % 65536
    if stored != computed:
        raise ValueError(
            "secret-key checksum mismatch: file says %04x, data is %04x"
            % (stored, computed)
        )

    print(seed.hex())


if __name__ == "__main__":
    main(sys.argv)
