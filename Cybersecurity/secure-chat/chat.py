"""Encrypted chat over a TCP socket.

One side runs as the server, the other connects as a client. They perform a
Diffie-Hellman key exchange in the clear, derive a shared key, and from then on
every message is sealed with ChaCha20-Poly1305. A network observer sees only the
public DH values and ciphertext.

    python chat.py server --port 9000
    python chat.py client --host 127.0.0.1 --port 9000

All the cryptography and framing live in `crypto` and `protocol`, which are
tested without a socket. This file wires them to the network and the terminal.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto import (  # noqa: E402
    AuthenticationError,
    derive_key,
    dh_generate_private,
    dh_public,
    dh_shared_secret,
)
from protocol import FrameReader, frame, open_message, seal_message  # noqa: E402

PUBLIC_VALUE_BYTES = 256  # a 2048-bit DH value


def send_public(sock: socket.socket, value: int) -> None:
    sock.sendall(frame(value.to_bytes(PUBLIC_VALUE_BYTES, "big")))


def receive_public(sock: socket.socket, reader: FrameReader) -> int:
    """Block until one complete framed public value has arrived."""
    while True:
        frames = reader.feed(sock.recv(4096))
        if frames:
            return int.from_bytes(frames[0], "big")
        # An empty recv means the peer closed before completing the handshake.


def handshake(sock: socket.socket, reader: FrameReader) -> bytes:
    """Exchange DH public values and derive the shared symmetric key."""
    private = dh_generate_private()
    send_public(sock, dh_public(private))
    their_public = receive_public(sock, reader)
    return derive_key(dh_shared_secret(their_public, private))


def receiver_loop(sock: socket.socket, reader: FrameReader, key: bytes, name: str) -> None:
    """Print incoming messages until the peer disconnects."""
    counter = 0
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            for sealed in reader.feed(data):
                try:
                    text = open_message(key, counter, sealed)
                except AuthenticationError:
                    print("\n[!] A message failed authentication and was dropped.")
                    continue
                counter += 1
                print(f"\r{name}: {text}\n> ", end="", flush=True)
    except OSError:
        pass
    print(f"\n[{name} disconnected]")


def sender_loop(sock: socket.socket, key: bytes) -> None:
    """Read lines from the terminal and send them sealed."""
    counter = 0
    try:
        while True:
            text = input("> ")
            if text in ("/quit", "/exit"):
                break
            sock.sendall(seal_message(key, counter, text))
            counter += 1
    except (EOFError, KeyboardInterrupt):
        pass
    except OSError:
        pass


def run_session(sock: socket.socket, key: bytes, peer_name: str) -> None:
    reader = FrameReader()
    receiver = threading.Thread(
        target=receiver_loop, args=(sock, reader, key, peer_name), daemon=True
    )
    receiver.start()
    print("Secure channel established. Type a message, or /quit to leave.\n")
    sender_loop(sock, key)
    sock.close()


def run_server(host: str, port: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"Listening on {host}:{port}. Waiting for a peer...")
        connection, address = server.accept()
        print(f"Connected to {address[0]}:{address[1]}")

        reader = FrameReader()
        key = handshake(connection, reader)
        run_session(connection, key, "peer")
    return 0


def run_client(host: str, port: int) -> int:
    try:
        connection = socket.create_connection((host, port), timeout=10)
    except OSError as exc:
        print(f"[!] Could not connect to {host}:{port}: {exc}", file=sys.stderr)
        return 1

    print(f"Connected to {host}:{port}")
    reader = FrameReader()
    key = handshake(connection, reader)
    run_session(connection, key, "peer")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="End-to-end encrypted chat over TCP")
    parser.add_argument("role", choices=("server", "client"), help="Which side to run")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind or connect to")
    parser.add_argument("--port", type=int, default=9000, help="Port")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not 0 < args.port <= 65535:
        print(f"[!] Port {args.port} is outside 1-65535.", file=sys.stderr)
        return 2
    try:
        if args.role == "server":
            return run_server(args.host, args.port)
        return run_client(args.host, args.port)
    except KeyboardInterrupt:
        print("\nClosed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
