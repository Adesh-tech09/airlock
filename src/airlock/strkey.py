"""Stellar strkey decoding and CRC16-XModem checksum. P1, task 6.2 (used by stellar_seed).

A seed candidate is only reported when the checksum validates. The byte contract is fixed by
`ARCHITECTURE.md` 9.4: 56 canonical uppercase unpadded RFC4648 Base32 characters decode to 35
bytes, which are one version byte `0x90`, the 32-byte seed and a little-endian CRC16-XMODEM over
the first 33 bytes.

Decoding is deliberately strict. A lowercase candidate, a padded one and one that merely decodes
to the right length are all rejected, because re-encoding must reproduce the candidate exactly.
Nothing here guesses whether a seed is funded, live or safe to publish; the checksum only says
the encoding is intact.
"""

from __future__ import annotations

import base64
import binascii

#: StrKey version byte for an Ed25519 secret seed (`18 << 3`).
SEED_VERSION = 0x90
#: Characters in a canonical seed, and bytes they decode to.
SEED_CHARACTERS = 56
SEED_BYTES = 35
#: Bytes covered by the checksum: the version byte plus the seed.
CHECKSUM_OFFSET = 33


def crc16_xmodem(data: bytes) -> int:
    """CRC16-XMODEM: polynomial `0x1021`, zero initial value, no reflection, no final XOR."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def decode_seed(candidate: str) -> bytes | None:
    """Return the 32-byte seed behind a checksum-valid candidate, or None.

    A candidate is accepted only when all of these hold: 56 characters, canonical uppercase
    Base32 that re-encodes to itself, 35 decoded bytes, version `0x90`, and a little-endian
    CRC16-XMODEM over the first 33 bytes that matches the last two.
    """
    if len(candidate) != SEED_CHARACTERS:
        return None
    try:
        decoded = base64.b32decode(candidate, casefold=False)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != SEED_BYTES:
        return None
    if base64.b32encode(decoded).decode("ascii") != candidate:
        return None
    if decoded[0] != SEED_VERSION:
        return None
    if crc16_xmodem(decoded[:CHECKSUM_OFFSET]) != int.from_bytes(
        decoded[CHECKSUM_OFFSET:], "little"
    ):
        return None
    return decoded[1:CHECKSUM_OFFSET]
