"""TLS certificate inspector.

Retrieves the certificate a host presents, reports who issued it, what names it
covers and when it expires, and flags anything worth worrying about.

The certificate is fetched twice on purpose: once with full verification to
learn whether the chain is trusted, and once without, so an expired or
self-signed certificate can still be read and explained rather than just refused.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from x509 import Certificate, DERError, parse_certificate  # noqa: E402

DEFAULT_PORT = 443
EXPIRY_WARNING_DAYS = 30
MINIMUM_RSA_BITS = 2048


class InspectionError(RuntimeError):
    """Raised when a certificate cannot be retrieved."""


@dataclass
class Inspection:
    host: str
    port: int
    certificate: Certificate
    trusted: bool
    trust_error: str | None
    tls_version: str | None
    cipher: str | None


def fetch_certificate(
    host: str,
    port: int,
    *,
    timeout: float,
    verify: bool,
    server_name: str | None = None,
) -> tuple[bytes, str | None, str | None]:
    """Return the peer certificate in DER form, plus the negotiated TLS details."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    sni = server_name or host
    try:
        socket.inet_pton(socket.AF_INET, sni)
        sni = None
    except OSError:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    raise InspectionError("The server presented no certificate")
                return der, tls_sock.version(), (tls_sock.cipher() or [None])[0]
    except ssl.SSLError as exc:
        raise InspectionError(f"TLS handshake failed: {exc}") from exc
    except OSError as exc:
        raise InspectionError(f"Connection failed: {exc}") from exc


def inspect(
    host: str,
    port: int,
    *,
    timeout: float,
    server_name: str | None = None,
) -> Inspection:
    """Fetch and parse a certificate, recording whether the chain verified."""
    trusted = True
    trust_error: str | None = None
    try:
        der, version, cipher = fetch_certificate(
            host, port, timeout=timeout, verify=True, server_name=server_name
        )
    except InspectionError as exc:
        trusted = False
        trust_error = str(exc)
        der, version, cipher = fetch_certificate(
            host, port, timeout=timeout, verify=False, server_name=server_name
        )

    try:
        certificate = parse_certificate(der)
    except DERError as exc:
        raise InspectionError(f"Could not parse the certificate: {exc}") from exc

    return Inspection(
        host=host,
        port=port,
        certificate=certificate,
        trusted=trusted,
        trust_error=trust_error,
        tls_version=version,
        cipher=cipher,
    )


def find_warnings(inspection: Inspection, *, now: datetime | None = None) -> list[str]:
    """Collect everything about this certificate worth reporting."""
    reference = now or datetime.now(timezone.utc)
    certificate = inspection.certificate
    warnings: list[str] = []

    if certificate.is_expired(reference):
        days = abs(certificate.days_until_expiry(reference))
        warnings.append(f"Expired {days} day(s) ago, on {certificate.not_after:%Y-%m-%d}")
    elif certificate.days_until_expiry(reference) <= EXPIRY_WARNING_DAYS:
        days = certificate.days_until_expiry(reference)
        warnings.append(f"Expires in {days} day(s), on {certificate.not_after:%Y-%m-%d}")

    if certificate.is_not_yet_valid(reference):
        warnings.append(f"Not valid until {certificate.not_before:%Y-%m-%d}")

    if certificate.is_self_signed:
        warnings.append("Self-signed: the issuer and the subject are the same entity")

    if certificate.has_weak_signature:
        warnings.append(f"Weak signature algorithm: {certificate.signature_algorithm}")

    if (
        certificate.public_key_algorithm == "RSA"
        and certificate.public_key_bits is not None
        and certificate.public_key_bits < MINIMUM_RSA_BITS
    ):
        warnings.append(
            f"RSA key is only {certificate.public_key_bits} bits, "
            f"below the {MINIMUM_RSA_BITS}-bit minimum"
        )

    if not inspection.trusted:
        warnings.append(f"Chain did not verify: {inspection.trust_error}")

    return warnings


def format_name(attributes: dict[str, str]) -> str:
    if not attributes:
        return "(empty)"
    order = ("CN", "O", "OU", "L", "ST", "C")
    ordered = [f"{key}={attributes[key]}" for key in order if key in attributes]
    extra = [f"{key}={value}" for key, value in attributes.items() if key not in order]
    return ", ".join(ordered + extra)


def build_report(inspection: Inspection, warnings: Sequence[str]) -> dict:
    certificate = inspection.certificate
    return {
        "host": inspection.host,
        "port": inspection.port,
        "trusted": inspection.trusted,
        "tls_version": inspection.tls_version,
        "cipher": inspection.cipher,
        "subject": certificate.subject,
        "issuer": certificate.issuer,
        "serial_number": f"{certificate.serial_number:x}",
        "not_before": certificate.not_before.isoformat(),
        "not_after": certificate.not_after.isoformat(),
        "days_until_expiry": certificate.days_until_expiry(),
        "signature_algorithm": certificate.signature_algorithm,
        "public_key": {
            "algorithm": certificate.public_key_algorithm,
            "bits": certificate.public_key_bits,
            "curve": certificate.public_key_curve,
        },
        "dns_names": certificate.dns_names,
        "ip_addresses": certificate.ip_addresses,
        "self_signed": certificate.is_self_signed,
        "warnings": list(warnings),
    }


def print_report(inspection: Inspection, warnings: Sequence[str], show_all_names: bool) -> None:
    certificate = inspection.certificate
    print(f"\nCertificate for {inspection.host}:{inspection.port}")
    print("-" * 60)
    print(f"Subject:    {format_name(certificate.subject)}")
    print(f"Issuer:     {format_name(certificate.issuer)}")
    print(f"Serial:     {certificate.serial_number:x}")
    print(f"Valid from: {certificate.not_before:%Y-%m-%d %H:%M} UTC")
    print(f"Valid to:   {certificate.not_after:%Y-%m-%d %H:%M} UTC")

    days = certificate.days_until_expiry()
    print(f"Expires in: {days} day(s)" if days >= 0 else f"Expired:    {abs(days)} day(s) ago")

    key = certificate.public_key_algorithm
    if certificate.public_key_curve:
        key += f" {certificate.public_key_curve}"
    if certificate.public_key_bits:
        key += f" ({certificate.public_key_bits} bits)"
    print(f"Public key: {key}")
    print(f"Signature:  {certificate.signature_algorithm}")

    if inspection.tls_version:
        print(f"Negotiated: {inspection.tls_version} with {inspection.cipher}")
    print(f"Trusted:    {'yes' if inspection.trusted else 'no'}")

    names = certificate.all_names()
    if names:
        shown = names if show_all_names else names[:8]
        print(f"\nNames ({len(names)}):")
        for name in shown:
            print(f"  {name}")
        if len(shown) < len(names):
            print(f"  ... and {len(names) - len(shown)} more, use --all-names")
    if certificate.ip_addresses:
        print(f"IP addresses: {', '.join(certificate.ip_addresses)}")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  [!] {warning}")
    else:
        print("\nNo warnings.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect the TLS certificate a host presents",
        epilog="Only inspect hosts you own or are authorised to test.",
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument(
        "port", nargs="?", type=int, default=DEFAULT_PORT, help="Target port (default 443)"
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds")
    parser.add_argument("--server-name", help="Hostname to send as SNI")
    parser.add_argument(
        "--all-names", action="store_true", help="Print every name in the certificate"
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with code 1 when any warning is raised, for use in CI",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if not 0 < args.port <= 65535:
        print(f"[!] Port {args.port} is outside 1-65535.", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("[!] --timeout must be greater than 0.", file=sys.stderr)
        return 2

    try:
        inspection = inspect(
            args.host, args.port, timeout=args.timeout, server_name=args.server_name
        )
    except InspectionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    warnings = find_warnings(inspection)

    if args.json:
        print(json.dumps(build_report(inspection, warnings), indent=2))
    else:
        print_report(inspection, warnings, args.all_names)

    return 1 if warnings and args.fail_on_warning else 0


if __name__ == "__main__":
    raise SystemExit(main())
