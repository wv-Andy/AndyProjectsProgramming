"""The wire protocol for the encrypted chat, kept apart from the sockets.

Two concerns live here so they can be tested without a network:

1. Framing. TCP is a byte stream, so each message is length-prefixed. This turns
   a stream back into discrete messages.
2. The message format. After the handshake, every message is sealed with
   ChaCha20-Poly1305 under a per-message nonce, so no plaintext is ever framed.
"""

from __future__ import annotations

import struct

from crypto import decrypt, encrypt

LENGTH_PREFIX = struct.Struct(">I")
MAX_MESSAGE = 1 << 20  # 1 MiB, a sanity cap on a single frame


def frame(payload: bytes) -> bytes:
    """Prefix a payload with its 4-byte big-endian length."""
    if len(payload) > MAX_MESSAGE:
        raise ValueError("Message exceeds the maximum frame size")
    return LENGTH_PREFIX.pack(len(payload)) + payload


class FrameReader:
    """Reassembles length-prefixed frames from a byte stream.

    Bytes arrive in whatever chunks TCP feels like delivering. This buffers them
    and yields complete frames only, which is the piece a naive `recv` loop
    always gets wrong.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """Add received bytes and return any complete frames now available."""
        self._buffer.extend(data)
        frames: list[bytes] = []

        while len(self._buffer) >= LENGTH_PREFIX.size:
            (length,) = LENGTH_PREFIX.unpack(self._buffer[: LENGTH_PREFIX.size])
            if length > MAX_MESSAGE:
                raise ValueError("Framed length exceeds the maximum")
            total = LENGTH_PREFIX.size + length
            if len(self._buffer) < total:
                break  # the rest of this frame has not arrived yet
            frames.append(bytes(self._buffer[LENGTH_PREFIX.size : total]))
            del self._buffer[:total]

        return frames


def nonce_for(counter: int) -> bytes:
    """A 12-byte nonce from a message counter.

    Each direction keeps its own counter, so a nonce is never reused under one
    key, which is the one rule you must not break with ChaCha20-Poly1305.
    """
    return counter.to_bytes(12, "big")


def seal_message(key: bytes, counter: int, text: str) -> bytes:
    """Encrypt a chat line into a frame ready to send."""
    sealed = encrypt(key, nonce_for(counter), text.encode("utf-8"))
    return frame(sealed)


def open_message(key: bytes, counter: int, sealed: bytes) -> str:
    """Decrypt and authenticate a received frame back into text."""
    plaintext = decrypt(key, nonce_for(counter), sealed)
    return plaintext.decode("utf-8", errors="replace")
