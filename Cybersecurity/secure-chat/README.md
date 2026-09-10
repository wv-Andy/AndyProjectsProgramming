# Encrypted Chat over Sockets

A two-party chat where the two sides agree on a key over an untrusted network
and encrypt every message. A network observer sees only public key-exchange
values and ciphertext. No dependencies.

The cipher, ChaCha20-Poly1305, is implemented by hand from RFC 8439 and
validated against that RFC's official test vectors. The key exchange is
Diffie-Hellman over the RFC 3526 2048-bit group.

> **Educational only.** A hand-rolled cipher is the right way to *learn* how one
> works and the wrong way to protect anything real. This code is not constant-time
> against every attack, has no forward secrecy across sessions, and is not
> audited. For real use, take a vetted library like `cryptography`.

## Features

- Diffie-Hellman key exchange, so no shared secret is ever transmitted
- ChaCha20-Poly1305 authenticated encryption, built from the RFC
- Tampered messages are detected and dropped, not shown
- Length-prefixed framing over TCP, handled correctly for split packets
- A per-message nonce counter, so no nonce is ever reused under a key
- Runs as a server or a client from one file

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

In one terminal:

```bash
python chat.py server --port 9000
```

In another, on the same or a different machine:

```bash
python chat.py client --host 127.0.0.1 --port 9000
```

Type a line and press enter to send. `/quit` leaves.

## How two strangers agree on a secret

Diffie-Hellman is the idea that makes the whole thing possible. Two parties who
have never met, talking over a wire an attacker is reading, can end up sharing a
secret the attacker cannot compute.

```
public, agreed in advance:  a large prime p and a generator g

Alice                                            Bob
  picks secret a                                   picks secret b
  sends g^a mod p  ───────────────────────────►
                   ◄───────────────────────────    sends g^b mod p
  computes (g^b)^a                                 computes (g^a)^b
        └──────────────  same value  ──────────────────┘
                    (g^a)^b == (g^b)^a  mod p
```

The eavesdropper sees `g`, `p`, `g^a` and `g^b`, and still cannot find the shared
value. Recovering `a` from `g^a mod p` is the **discrete logarithm problem**, and
for a 2048-bit prime it is infeasible. The shared integer is then run through
SHA-256 to make a 32-byte symmetric key.

## Why ChaCha20-Poly1305

Once both sides share a key, they need to encrypt with it. ChaCha20-Poly1305 is
an **AEAD** cipher: authenticated encryption with associated data. It does two
jobs at once.

- **ChaCha20** is the stream cipher. It turns the key, a nonce and a counter into
  a keystream, and the message is XORed with it. Encryption and decryption are
  the same operation.
- **Poly1305** is the authenticator. It produces a 16-byte tag over the
  ciphertext. If a single bit is flipped in transit, the tag will not match and
  the message is rejected.

Encryption without authentication is a classic mistake: an attacker who cannot
read a message can still flip bits in it and change what it decrypts to. The tag
closes that hole. `decrypt` verifies it in constant time before returning
anything, and raises rather than hand back tampered data.

## The one rule: never reuse a nonce

With a stream cipher, encrypting two messages under the same key and nonce is
catastrophic. XOR the two ciphertexts and the keystream cancels out, leaking the
messages. So each direction keeps a message counter and derives the nonce from
it, guaranteeing every message under a key uses a fresh nonce.

## Proof it works

An integration test runs both sides over a real socket, captures the bytes on
the wire, and asserts the plaintext is not among them:

```
server decrypted: attack at dawn
keys match: True
plaintext on the wire: False
wire bytes (hex): 0000001eda506613a720002ebd88f1d4...
```

The message arrived intact, both sides derived the same key, and the words never
appeared unencrypted on the connection.

## Design notes

**Crypto, protocol and network are three layers.** [`crypto.py`](crypto.py) is
pure maths, validated against RFC vectors. [`protocol.py`](protocol.py) does
framing and per-message sealing, tested without a socket. [`chat.py`](chat.py)
wires them to TCP and the terminal. Each layer is tested at its own level.

**Framing is not optional.** TCP is a byte stream with no message boundaries, so
`recv` can return half a message or three at once. `FrameReader` buffers bytes
and yields only complete, length-prefixed frames. This is the bug every first
socket program has, and the tests cover the split and combined cases directly.

## What I learned

- The Diffie-Hellman exchange, and why the discrete log problem protects it
- How a stream cipher and a MAC combine into authenticated encryption
- Why unauthenticated encryption is a real, exploitable mistake
- That nonce reuse breaks a stream cipher completely, and how to prevent it
- Implementing a cipher against published test vectors, which is how you know it
  is correct rather than merely consistent with itself
- Why you still should not roll your own crypto for production

## Disclaimer

Educational. Not audited, not constant-time everywhere, no forward secrecy. Do
not protect real secrets with this.

## License

MIT, see [LICENSE](../../LICENSE).
