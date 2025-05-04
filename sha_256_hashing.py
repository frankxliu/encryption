import struct
from functools import reduce

"""
This was created by following the SHA256 steps here: https://github.com/liangtengyu/wx_gzh_article/blob/master/How%20SHA-2%20Works%20Step-By-Step%20(SHA-256).md
=== What is SHA256? ===
SHA256 is a cryptographically safe hashing function that is part of the SHA-2 family and
produces a 256-bit hash value, represented as a 64-char hexidecimal number.

=== Strengths ===
SHA256 is resistant to collisions. This makes the algorithm reliable in preserving the
integrity and security of data. It finds itself used to secure communications and
digital signatures, backing blockchain technology.

=== Weaknesses ===
Where resources are a luxury, SHA256 requires more computation. Since the hash output
is 256-bits, more storage and bandwith is required. Such case would be commonly seen in 
low-powered/iot devices.
"""


class Sha256:
    WORD_BIT_LEN = 32

    def __init__(self, message):
        self.message = str(message).encode("utf-8")

    def right_rotate(self, bits, shift):
        """
        Circularly shift bits to the right by 'shift' places. Uses
        this class' right_shift method.
        """
        shift = shift % self.WORD_BIT_LEN
        return self.right_shift(bits, shift) | (
            bits << self.WORD_BIT_LEN - shift
        ) & int("FF" * (self.WORD_BIT_LEN // 8), 16)

    def right_shift(self, bits, shift):
        """
        Shift bits to the right by 'shift' places.
        """
        shift = shift % self.WORD_BIT_LEN
        return (bits >> shift) & ((1 << self.WORD_BIT_LEN) - 1)

    def hash(self):
        self.padded_data = (
            self.message
            + b"\x80"
            + b"\x00" * ((56 - len(self.message) - 1) % 64)
            + struct.pack(">Q", len(self.message) * 8)
        )

        h_ = [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]

        k = [
            0x428A2F98,
            0x71374491,
            0xB5C0FBCF,
            0xE9B5DBA5,
            0x3956C25B,
            0x59F111F1,
            0x923F82A4,
            0xAB1C5ED5,
            0xD807AA98,
            0x12835B01,
            0x243185BE,
            0x550C7DC3,
            0x72BE5D74,
            0x80DEB1FE,
            0x9BDC06A7,
            0xC19BF174,
            0xE49B69C1,
            0xEFBE4786,
            0x0FC19DC6,
            0x240CA1CC,
            0x2DE92C6F,
            0x4A7484AA,
            0x5CB0A9DC,
            0x76F988DA,
            0x983E5152,
            0xA831C66D,
            0xB00327C8,
            0xBF597FC7,
            0xC6E00BF3,
            0xD5A79147,
            0x06CA6351,
            0x14292967,
            0x27B70A85,
            0x2E1B2138,
            0x4D2C6DFC,
            0x53380D13,
            0x650A7354,
            0x766A0ABB,
            0x81C2C92E,
            0x92722C85,
            0xA2BFE8A1,
            0xA81A664B,
            0xC24B8B70,
            0xC76C51A3,
            0xD192E819,
            0xD6990624,
            0xF40E3585,
            0x106AA070,
            0x19A4C116,
            0x1E376C08,
            0x2748774C,
            0x34B0BCB5,
            0x391C0CB3,
            0x4ED8AA4A,
            0x5B9CCA4F,
            0x682E6FF3,
            0x748F82EE,
            0x78A5636F,
            0x84C87814,
            0x8CC70208,
            0x90BEFFFA,
            0xA4506CEB,
            0xBEF9A3F7,
            0xC67178F2,
        ]

        # Partition padded message into 512-bit chunks
        for i in range(0, len(self.padded_data), 64):
            chunk = self.padded_data[i : i + 64]

            # Partition each chunk into separate array of 32-bit words
            w = [int.from_bytes(chunk[i : i + 4]) for i in range(0, len(chunk), 4)]

            # Extend array such that it has 64 words
            w.extend([int.from_bytes(bytes(4)) for i in range(0, 48)])

            for i in range(16, len(w)):
                s0 = (
                    self.right_rotate(w[i - 15], 7)
                    ^ self.right_rotate(w[i - 15], 18)
                    ^ self.right_shift(w[i - 15], 3)
                )
                s1 = (
                    self.right_rotate(w[i - 2], 17)
                    ^ self.right_rotate(w[i - 2], 19)
                    ^ self.right_shift(w[i - 2], 10)
                )
                # Applying 32-bit bitmask is important here to preserve word size
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = (
                h_[0],
                h_[1],
                h_[2],
                h_[3],
                h_[4],
                h_[5],
                h_[6],
                h_[7],
            )

            for i in range(0, len(w)):
                s1 = (
                    self.right_rotate(e, 6)
                    ^ self.right_rotate(e, 11)
                    ^ self.right_rotate(e, 25)
                )
                ch = (e & f) ^ (~e & g)
                temp1 = h + s1 + ch + k[i] + w[i] & 0xFFFFFFFF
                s0 = (
                    self.right_rotate(a, 2)
                    ^ self.right_rotate(a, 13)
                    ^ self.right_rotate(a, 22)
                )
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = s0 + maj & 0xFFFFFFFF

                h, g, f, e, d, c, b, a = (
                    g,
                    f,
                    e,
                    d + temp1 & 0xFFFFFFFF,
                    c,
                    b,
                    a,
                    temp1 + temp2 & 0xFFFFFFFF,
                )

            h_ = [
                h_[0] + a & 0xFFFFFFFF,
                h_[1] + b & 0xFFFFFFFF,
                h_[2] + c & 0xFFFFFFFF,
                h_[3] + d & 0xFFFFFFFF,
                h_[4] + e & 0xFFFFFFFF,
                h_[5] + f & 0xFFFFFFFF,
                h_[6] + g & 0xFFFFFFFF,
                h_[7] + h & 0xFFFFFFFF,
            ]

        digest = ("{:08x}" * 8).format(*h_)
        return digest


hash2 = Sha256("hello world").hash()
print(hash2)
