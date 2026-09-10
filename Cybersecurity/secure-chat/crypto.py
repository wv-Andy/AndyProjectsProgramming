"""ChaCha20-Poly1305 and Diffie-Hellman, implemented from the RFCs.

Python has no AEAD cipher in the standard library, and the point of this project
is to understand the primitive rather than import it. So ChaCha20 and Poly1305
are written out here from RFC 8439, and the finished cipher is validated against
that RFC's official test vectors in the test suite. Diffie-Hellman uses the 2048
bit MODP group from RFC 3526.

This is educational code. For anything real, use a vetted library such as
`cryptography`. A hand-rolled cipher has no protection against timing attacks and
has not been audited.
"""

from __future__ import annotations

import hashlib
import os
import struct

MASK32 = 0xFFFFFFFF


# --- ChaCha20 (RFC 8439 section 2) ----------------------------------------


def _rotl32(value: int, count: int) -> int:
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """The ChaCha quarter-round, mutating four words of the state in place."""
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


# The constant is the ASCII of "expand 32-byte k", as four little-endian words.
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Produce one 64-byte keystream block."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    state = [*_CONSTANTS, *key_words, counter & MASK32, *nonce_words]
    working = list(state)

    # Twenty rounds: ten column rounds and ten diagonal rounds, interleaved.
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    # Add the original state back in, so the round function is not invertible.
    out = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """XOR the data with the ChaCha20 keystream. Encryption and decryption are
    the same operation."""
    out = bytearray()
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        out.extend(byte ^ block[index] for index, byte in enumerate(chunk))
    return bytes(out)


# --- Poly1305 (RFC 8439 section 2.5) --------------------------------------

_POLY_P = (1 << 130) - 5


def poly1305_mac(key: bytes, message: bytes) -> bytes:
    """Compute the 16-byte Poly1305 tag for a message under a one-time key."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r = int.from_bytes(key[:16], "little")
    # Clamp r, as the spec requires.
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")

    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16]
        # Append a 1 bit above the chunk's bytes.
        n = int.from_bytes(chunk + b"\x01", "little")
        accumulator = (accumulator + n) % _POLY_P
        accumulator = (accumulator * r) % _POLY_P

    accumulator = (accumulator + s) & ((1 << 128) - 1)
    return accumulator.to_bytes(16, "little")


def _poly1305_key(key: bytes, nonce: bytes) -> bytes:
    """Derive the one-time Poly1305 key from the ChaCha20 keystream, block 0."""
    return chacha20_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    """Zero-pad to the next 16-byte boundary, as the AEAD construction requires."""
    remainder = len(data) % 16
    return b"\x00" * (16 - remainder) if remainder else b""


def _aead_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


class AuthenticationError(Exception):
    """Raised when a ciphertext's tag does not verify."""


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD encrypt: returns ciphertext followed by the 16-byte tag."""
    otk = _poly1305_key(key, nonce)
    # Data encryption starts at counter 1; counter 0 made the Poly1305 key.
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    tag = poly1305_mac(otk, _aead_mac_data(aad, ciphertext))
    return ciphertext + tag


def decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """AEAD decrypt: verifies the tag, then returns the plaintext."""
    if len(sealed) < 16:
        raise AuthenticationError("Ciphertext is too short to contain a tag")
    ciphertext, tag = sealed[:-16], sealed[-16:]

    otk = _poly1305_key(key, nonce)
    expected = poly1305_mac(otk, _aead_mac_data(aad, ciphertext))

    # Constant-time comparison, so a wrong tag leaks no timing information.
    if not _constant_time_equal(tag, expected):
        raise AuthenticationError("Tag mismatch: the message was tampered with or corrupted")

    return chacha20_encrypt(key, 1, nonce, ciphertext)


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    difference = 0
    for x, y in zip(a, b, strict=True):
        difference |= x ^ y
    return difference == 0


# --- Diffie-Hellman (RFC 3526, 2048-bit MODP group 14) --------------------

# A safe prime and generator, published in RFC 3526. Both sides agree on these.
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2


def dh_generate_private() -> int:
    """A random private exponent, 256 bits of entropy from the OS."""
    return int.from_bytes(os.urandom(32), "big")


def dh_public(private: int) -> int:
    """The public value g^private mod p, safe to send in the clear."""
    return pow(DH_GENERATOR, private, DH_PRIME)


def dh_shared_secret(their_public: int, my_private: int) -> int:
    """The shared secret (their_public)^my_private mod p.

    Both sides compute the same value: (g^a)^b == (g^b)^a mod p. An eavesdropper
    sees g, p, g^a and g^b, and cannot feasibly recover the secret. That gap is
    the discrete logarithm problem.
    """
    if not 1 < their_public < DH_PRIME - 1:
        raise ValueError("Invalid public value")
    return pow(their_public, my_private, DH_PRIME)


def derive_key(shared_secret: int) -> bytes:
    """Turn the DH shared integer into a 32-byte symmetric key with SHA-256."""
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    return hashlib.sha256(secret_bytes).digest()
