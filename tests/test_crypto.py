"""Tests for the hand-written ChaCha20-Poly1305 and Diffie-Hellman.

The cipher is validated against the official test vectors in RFC 8439. Matching
those byte for byte is the proof that the implementation is correct, not just
self-consistent.
"""

from __future__ import annotations

import pytest

# --- ChaCha20 block, RFC 8439 section 2.3.2 -------------------------------


def test_chacha20_block_matches_the_rfc_vector(crypto):
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = crypto.chacha20_block(key, 1, nonce)
    # First 16 bytes of the expected keystream from the RFC.
    expected_start = bytes.fromhex("10f1e7e4d13b5915500fdd1fa32071c4")
    assert block[:16] == expected_start


# --- ChaCha20 encryption, RFC 8439 section 2.4.2 --------------------------


def test_chacha20_encrypt_matches_the_rfc_vector(crypto):
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    ciphertext = crypto.chacha20_encrypt(key, 1, nonce, plaintext)
    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    assert ciphertext == expected


def test_chacha20_is_symmetric(crypto):
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"the same operation both ways"
    ciphertext = crypto.chacha20_encrypt(key, 1, nonce, plaintext)
    assert crypto.chacha20_encrypt(key, 1, nonce, ciphertext) == plaintext


# --- Poly1305, RFC 8439 section 2.5.2 -------------------------------------


def test_poly1305_matches_the_rfc_vector(crypto):
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    message = b"Cryptographic Forum Research Group"
    tag = crypto.poly1305_mac(key, message)
    assert tag == bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")


# --- AEAD, RFC 8439 section 2.8.2 -----------------------------------------


def test_aead_encrypt_matches_the_rfc_vector(crypto):
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    sealed = crypto.encrypt(key, nonce, plaintext, aad)

    expected_ciphertext = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    assert sealed == expected_ciphertext + expected_tag


def test_aead_round_trip(crypto):
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"a secret message"
    sealed = crypto.encrypt(key, nonce, plaintext, aad=b"header")
    assert crypto.decrypt(key, nonce, sealed, aad=b"header") == plaintext


def test_decrypt_rejects_a_tampered_ciphertext(crypto):
    key = bytes(range(32))
    nonce = bytes(range(12))
    sealed = bytearray(crypto.encrypt(key, nonce, b"important", aad=b""))
    sealed[0] ^= 0x01  # flip one bit of the ciphertext
    with pytest.raises(crypto.AuthenticationError):
        crypto.decrypt(key, nonce, bytes(sealed), aad=b"")


def test_decrypt_rejects_a_tampered_tag(crypto):
    key = bytes(range(32))
    nonce = bytes(range(12))
    sealed = bytearray(crypto.encrypt(key, nonce, b"important"))
    sealed[-1] ^= 0x01  # flip one bit of the tag
    with pytest.raises(crypto.AuthenticationError):
        crypto.decrypt(key, nonce, bytes(sealed))


def test_decrypt_rejects_wrong_aad(crypto):
    key = bytes(range(32))
    nonce = bytes(range(12))
    sealed = crypto.encrypt(key, nonce, b"message", aad=b"real-header")
    with pytest.raises(crypto.AuthenticationError):
        crypto.decrypt(key, nonce, sealed, aad=b"fake-header")


def test_decrypt_rejects_a_short_input(crypto):
    with pytest.raises(crypto.AuthenticationError):
        crypto.decrypt(bytes(32), bytes(12), b"tooshort")


# --- Diffie-Hellman -------------------------------------------------------


def test_both_sides_derive_the_same_secret(crypto):
    alice_private = crypto.dh_generate_private()
    bob_private = crypto.dh_generate_private()

    alice_public = crypto.dh_public(alice_private)
    bob_public = crypto.dh_public(bob_private)

    alice_secret = crypto.dh_shared_secret(bob_public, alice_private)
    bob_secret = crypto.dh_shared_secret(alice_public, bob_private)

    assert alice_secret == bob_secret


def test_derived_keys_match_and_are_32_bytes(crypto):
    a_priv = crypto.dh_generate_private()
    b_priv = crypto.dh_generate_private()
    a_pub = crypto.dh_public(a_priv)
    b_pub = crypto.dh_public(b_priv)

    a_key = crypto.derive_key(crypto.dh_shared_secret(b_pub, a_priv))
    b_key = crypto.derive_key(crypto.dh_shared_secret(a_pub, b_priv))

    assert a_key == b_key
    assert len(a_key) == 32


def test_different_pairs_derive_different_secrets(crypto):
    priv1 = crypto.dh_generate_private()
    priv2 = crypto.dh_generate_private()
    # Two independent private keys yield different public values.
    assert crypto.dh_public(priv1) != crypto.dh_public(priv2)


def test_dh_rejects_an_out_of_range_public(crypto):
    with pytest.raises(ValueError):
        crypto.dh_shared_secret(1, crypto.dh_generate_private())
    with pytest.raises(ValueError):
        crypto.dh_shared_secret(crypto.DH_PRIME, crypto.dh_generate_private())


def test_end_to_end_key_exchange_then_message(crypto):
    """The whole flow: exchange keys, then send an authenticated message."""
    a_priv, b_priv = crypto.dh_generate_private(), crypto.dh_generate_private()
    a_pub, b_pub = crypto.dh_public(a_priv), crypto.dh_public(b_priv)

    key = crypto.derive_key(crypto.dh_shared_secret(b_pub, a_priv))
    nonce = bytes(range(12))

    sealed = crypto.encrypt(key, nonce, b"hello over an untrusted wire")

    # Bob derives the identical key and reads the message.
    bob_key = crypto.derive_key(crypto.dh_shared_secret(a_pub, b_priv))
    assert crypto.decrypt(bob_key, nonce, sealed) == b"hello over an untrusted wire"
