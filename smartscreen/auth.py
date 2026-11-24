"""SmartScreenHash request signing, translated from the collected ARM64 DLL.

Evidence: analysis/cs64_algorithms.json and analysis/cs64_constants.json.
This is the client protocol's body checksum; no account ticket is required here.
"""
import base64
import hashlib
import json
import struct

EDGE_AUTH_ID = '381ddd1e-e600-42de-94ed-8c34bf73f16d'
MASK32 = 0xffffffff


def u32(value):
    return value & MASK32


def cs64(body, key):
    """Native CS64WordSwap XOR CS64Reversible; incomplete 8-byte tails ignored."""
    if len(key) != 16:
        raise ValueError('CS64 key must contain 16 bytes')
    count = (len(body) // 4) & ~1
    if count < 2:
        raise ValueError('CS64 requires at least 8 body bytes')
    a, b = struct.unpack_from('<II', key)
    a, b = a | 1, b | 1
    swap_state = swap_sum = rev_state = rev_sum = 0
    for offset in range(0, count * 4, 8):
        first, second = struct.unpack_from('<II', body, offset)
        x = u32(first + swap_state)
        x = u32(u32(a + 0x69fb0000) * x - (x >> 16) * 0x10fa9605)
        x = u32((x >> 16) * 0x689b6b9f + x * 0x79f8a395)
        first_mix = u32(x * 0xea970001 - (x >> 16) * 0x3c101569)
        x = u32(second + first_mix)
        x = u32(u32(b + 0x13db0000) * x - (x >> 16) * 0x3ce8ec25)
        x = u32(x * 0x59c3af2d - (x >> 16) * 0x2232e0f1)
        swap_state = u32((x >> 16) * 0x35bd1ec9 + x * 0x1ec90001)
        swap_sum = u32(swap_sum + swap_state + first_mix)

        x = u32((first + rev_state) * a)
        p = u32((x >> 16) * 0x30674eef)
        q = u32((u32(x * -0x4eef0000 - p) >> 16) * 0x78f7a461)
        p = u32((u32(p * -0x5b9f0000 - q) >> 16) * 0x12ceb96d)
        first_mix = u32((u32(p + q * 0x46930000) >> 16) * 0x257e1d83 + p * 0x1d830000)
        x = u32((second + first_mix) * b)
        p = u32((x >> 16) * 0x5d8be90b)
        q = u32((u32(x * 0x16f50000 - p) >> 16) * 0x2c7c6901)
        p = u32((u32(p * 0x69010000 - q) >> 16) * 0x7c932b89)
        rev_state = u32(p * -0x60970000 - (u32(p + q * -0x2b890000) >> 16) * 0x405b6097)
        rev_sum = u32(rev_sum + rev_state + first_mix)
    return struct.pack('<II', swap_state ^ rev_state, swap_sum ^ rev_sum)


def authorization(body, auth_id=EDGE_AUTH_ID):
    key = hashlib.md5(body).digest()
    payload = {'authId': auth_id, 'key': base64.b64encode(key).decode(),
               'hash': base64.b64encode(cs64(body, key)).decode()}
    return 'SmartScreenHash ' + base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()
