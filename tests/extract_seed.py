#!/usr/bin/env python3
"""Extract the secret seed from a pass2key armored secret-key block."""

import base64
import sys


def packet_length(data, offset):
    first = data[offset]
    if first < 192:
        return first, 1
    if first < 224:
        return ((first - 192) << 8) + data[offset + 1] + 192, 2
    if first == 255:
        value = int.from_bytes(data[offset + 1:offset + 5], "big")
        return value, 5
    raise ValueError("unexpected packet length encoding")


def main(path):
    lines = open(path, "r", encoding="ascii").read().splitlines()
    encoded = []
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            continue
        if line == "":
            in_body = True
            continue
        if line.startswith("=") or line.startswith("-----END "):
            break
        if in_body:
            encoded.append(line)

    data = base64.b64decode("".join(encoded))
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
    print(seed.hex())


if __name__ == "__main__":
    main(sys.argv[1])
