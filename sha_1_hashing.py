import hashlib
import struct
import sys

"""
This was created by following SHA1 steps provided here: https://cis.temple.edu/~ingargio/cis307/readings/sha1.html

=== What is SHA1? ===
A cryptographic hash function that producesa 160-bit hash value, represented as a 40-char hexidecimal
number. It is mainly used in securing digital signatures, certificates and representing integrity of
data.

=== Strengths ===
SHA1 is computationally fast, and is not process intensive. This makes the algorithm suitable
for old legacy systems. However, on a relative and realistic scope, computation power in 
more modern algorithms are negligent based on Moore's Law. SHA1 is also widely supported
across many platforms and systems.

=== Weaknesses ===
SHA1 is vulnerable to collision attacks, where two different inputs result in the same hash value.
Thus, SHA1 hashing algorithm is deprecated and is not recommended in securing applications.
"""

# TODO: make this into a class, and clean up the code


# 32-bit word, or 8 hex digits
def logical_function(b, c, d, t):
    if 0 <= t <= 19:
        return (b & c) | ((~b) & d)
    elif 20 <= t <= 39:
        return b ^ c ^ d
    elif 40 <= t <= 59:
        return (b & c) | (b & d) | (c & d)
    else:  # 60 <=t <= 79
        return b ^ c ^ d


def get_constant(t):
    # Constants used during hashing
    K1 = 0x5A827999  # 0 <= t <= 19
    K2 = 0x6ED9EBA1  # 20 <= t <= 39
    K3 = 0x8F1BBCDC  # 40 <= t <= 59
    K4 = 0xCA62C1D6  # 60 <= t <= 79

    if 0 <= t <= 19:
        return K1
    elif 20 <= t <= 39:
        return K2
    elif 40 <= t <= 59:
        return K3
    else:  # 60 <=t <= 79
        return K4


def circular_left_shift(num, shift, size):
    shift = shift % size
    return (num << shift) & ((1 << size) - 1) | (num >> (size - shift)) & 0xFFFFFFFF


def sha_1_hash(message):
    byte_data = message.encode("utf-8")
    WORD_LEN = 32

    padded_data = (
        byte_data
        + b"\x80"
        + b"\x00" * ((56 - len(byte_data) - 1) % 64)
        + struct.pack(">Q", len(byte_data) * 8)
    )

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # computation uses 2 buffers, each consisting of 5 32-bit words and
    # sequence of 80 32-bit words. Single word buffer TEMP is also used.

    words = []
    prev_i = 0
    for i in range(0, len(padded_data), 64):
        prev_j = 0

        for j in range(4, 64 + 1, 4):
            words.append(int.from_bytes(padded_data[prev_j:j]))
            prev_j = j

        for k in range(16, 80):
            words.append(
                circular_left_shift(
                    words[k - 3] ^ words[k - 8] ^ words[k - 14] ^ words[k - 16],
                    1,
                    WORD_LEN,
                )
            )

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for t in range(80):
            temp = (
                circular_left_shift(a, 5, WORD_LEN)
                + logical_function(b, c, d, t)
                + e
                + words[t]
                + get_constant(t)
                & 0xFFFFFFFF
            )
            e, d, c, b, a = (d, c, circular_left_shift(b, 30, WORD_LEN), a, temp)

        h0, h1, h2, h3, h4 = (
            h0 + a & 0xFFFFFFFF,
            h1 + b & 0xFFFFFFFF,
            h2 + c & 0xFFFFFFFF,
            h3 + d & 0xFFFFFFFF,
            h4 + e & 0xFFFFFFFF,
        )

        ret = ("{:08x}" * 5).format(*[h0, h1, h2, h3, h4])
    return ret


print(sha_1_hash("abcdefg"))
