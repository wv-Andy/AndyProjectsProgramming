"""Live packet sniffer.

Captures frames from a raw socket and decodes them with the layer functions in
`decode`. The capture path differs by platform, and both need elevated rights:

- Linux uses AF_PACKET, which delivers full Ethernet frames.
- Windows uses a raw IP socket with SIO_RCVALL, which delivers IP packets with
  no Ethernet header, so decoding starts one layer up.

All the byte parsing lives in `decode`, which is why this file is short and the
tests never need a socket.
"""

from __future__ import annotations

import argparse
import socket
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from decode import (  # noqa: E402
    TCP,
    UDP,
    Packet,
    decode_packet,
    summarise,
)


class CaptureError(RuntimeError):
    """Raised when a capture socket cannot be opened."""


def open_capture() -> tuple[socket.socket, bool]:
    """Open a capture socket for the current platform.

    Returns the socket and whether its frames carry an Ethernet header.
    """
    if sys.platform.startswith("linux"):
        try:
            # ETH_P_ALL = 3, in network byte order.
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except (AttributeError, OSError) as exc:
            raise CaptureError(f"Could not open AF_PACKET socket: {exc}") from exc
        return sock, True

    if sys.platform == "win32":
        host = socket.gethostbyname(socket.gethostname())
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except (AttributeError, OSError) as exc:
            raise CaptureError(
                f"Could not open raw socket on {host}: {exc}. "
                "Run as Administrator."
            ) from exc
        return sock, False

    raise CaptureError(f"Packet capture is not supported on {sys.platform}")


def matches_filter(
    packet: Packet,
    *,
    protocol: str | None,
    port: int | None,
) -> bool:
    """Apply the command-line filters to a decoded packet."""
    if protocol is None and port is None:
        return True

    network = packet.network
    transport = packet.transport

    if protocol is not None:
        wanted = protocol.upper()
        actual = network.protocol_name.upper() if network else ""
        if wanted != actual:
            return False

    if port is not None:
        if not isinstance(transport, (TCP, UDP)):
            return False
        if port not in (transport.source_port, transport.destination_port):
            return False

    return True


def capture(
    *,
    count: int,
    protocol: str | None,
    port: int | None,
    on_packet,
) -> Counter:
    """Capture and decode packets until `count` is reached, or forever if 0."""
    sock, link_layer = open_capture()
    stats: Counter = Counter()
    seen = 0

    try:
        while count == 0 or seen < count:
            try:
                data = sock.recv(65535)
            except OSError as exc:
                raise CaptureError(f"Capture failed: {exc}") from exc

            packet = decode_packet(data, link_layer=link_layer)
            if not matches_filter(packet, protocol=protocol, port=port):
                continue

            seen += 1
            if packet.network is not None:
                stats[packet.network.protocol_name] += 1
            else:
                stats["non-IP"] += 1
            on_packet(seen, packet)
    finally:
        _close_capture(sock)

    return stats


def _close_capture(sock: socket.socket) -> None:
    if sys.platform == "win32":
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
    sock.close()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and decode live network traffic",
        epilog="Needs root on Linux or Administrator on Windows. Capture only on "
        "networks you are authorised to monitor.",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=20, help="Packets to capture, 0 for endless"
    )
    parser.add_argument(
        "-p", "--protocol", choices=("tcp", "udp", "icmp"), help="Only show this protocol"
    )
    parser.add_argument("--port", type=int, help="Only show packets to or from this port")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show packet counters at the end"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.port is not None and not 0 < args.port <= 65535:
        print(f"[!] Port {args.port} is outside 1-65535.", file=sys.stderr)
        return 2

    def show(index: int, packet: Packet) -> None:
        print(f"{index:>5}  {summarise(packet)}")

    protocol = args.protocol
    print(
        f"Capturing {'endlessly' if args.count == 0 else args.count} "
        f"packet(s){f', {protocol} only' if protocol else ''}"
        f"{f', port {args.port}' if args.port else ''}. Ctrl+C to stop.\n"
    )

    try:
        stats = capture(count=args.count, protocol=protocol, port=args.port, on_packet=show)
    except CaptureError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0

    if args.verbose and stats:
        print("\nProtocol counts:")
        for name, number in stats.most_common():
            print(f"  {name:<8} {number}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
