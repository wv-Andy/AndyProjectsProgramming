"""Tests for the chat framing and message sealing."""

from __future__ import annotations

import pytest

# --- Framing --------------------------------------------------------------


def test_frame_prefixes_the_length(protocol):
    framed = protocol.frame(b"hello")
    assert framed == b"\x00\x00\x00\x05hello"


def test_reader_returns_a_whole_frame(protocol):
    reader = protocol.FrameReader()
    assert reader.feed(protocol.frame(b"hello")) == [b"hello"]


def test_reader_reassembles_a_split_frame(protocol):
    """The whole point: a frame delivered in pieces still comes back whole."""
    reader = protocol.FrameReader()
    framed = protocol.frame(b"a longer message")
    assert reader.feed(framed[:3]) == []
    assert reader.feed(framed[3:10]) == []
    assert reader.feed(framed[10:]) == [b"a longer message"]


def test_reader_splits_two_frames_in_one_chunk(protocol):
    reader = protocol.FrameReader()
    combined = protocol.frame(b"first") + protocol.frame(b"second")
    assert reader.feed(combined) == [b"first", b"second"]


def test_reader_handles_a_frame_and_a_half(protocol):
    reader = protocol.FrameReader()
    stream = protocol.frame(b"complete") + protocol.frame(b"partial")[:2]
    assert reader.feed(stream) == [b"complete"]
    # The partial frame stays buffered until the rest arrives.


def test_frame_rejects_an_oversized_payload(protocol):
    with pytest.raises(ValueError):
        protocol.frame(b"x" * (protocol.MAX_MESSAGE + 1))


def test_reader_rejects_an_oversized_length(protocol):
    reader = protocol.FrameReader()
    import struct

    bad = struct.pack(">I", protocol.MAX_MESSAGE + 1)
    with pytest.raises(ValueError):
        reader.feed(bad)


# --- Nonces ---------------------------------------------------------------


def test_nonce_is_twelve_bytes(protocol):
    assert len(protocol.nonce_for(0)) == 12


def test_nonces_differ_per_counter(protocol):
    assert protocol.nonce_for(0) != protocol.nonce_for(1)


# --- Sealed messages ------------------------------------------------------


def test_seal_then_open_round_trip(protocol):
    key = bytes(range(32))
    framed = protocol.seal_message(key, 0, "hello world")
    reader = protocol.FrameReader()
    sealed = reader.feed(framed)[0]
    assert protocol.open_message(key, 0, sealed) == "hello world"


def test_sealed_message_is_not_plaintext(protocol):
    key = bytes(range(32))
    framed = protocol.seal_message(key, 0, "secret text")
    assert b"secret text" not in framed


def test_open_with_the_wrong_counter_fails(protocol, crypto):
    key = bytes(range(32))
    framed = protocol.seal_message(key, 0, "hello")
    reader = protocol.FrameReader()
    sealed = reader.feed(framed)[0]
    # A counter mismatch changes the nonce, so authentication fails.
    with pytest.raises(crypto.AuthenticationError):
        protocol.open_message(key, 1, sealed)


def test_open_with_the_wrong_key_fails(protocol, crypto):
    framed = protocol.seal_message(bytes(range(32)), 0, "hello")
    reader = protocol.FrameReader()
    sealed = reader.feed(framed)[0]
    wrong_key = bytes([0] * 32)
    with pytest.raises(crypto.AuthenticationError):
        protocol.open_message(wrong_key, 0, sealed)


def test_unicode_survives_the_round_trip(protocol):
    key = bytes(range(32))
    message = "hola, ¿qué tal? 🔐 café"
    framed = protocol.seal_message(key, 5, message)
    reader = protocol.FrameReader()
    sealed = reader.feed(framed)[0]
    assert protocol.open_message(key, 5, sealed) == message
