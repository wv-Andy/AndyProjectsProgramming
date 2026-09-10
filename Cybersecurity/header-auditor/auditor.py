"""HTTP security header auditor.

Fetches a URL, grades the security headers it sends back, and explains what each
missing one leaves exposed. The grade is the point: raw headers are data, a
graded report is a finding someone can act on.
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

USER_AGENT = "header-auditor/1.0"
MAX_REDIRECTS = 5

# Headers that leak information about the stack behind the service.
DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


@dataclass
class Check:
    """One security header and what it is worth."""

    header: str
    weight: int
    summary: str
    exposure: str
    validate: Callable[[str], tuple[bool, str]] | None = None


@dataclass
class Finding:
    header: str
    present: bool
    value: str | None
    passed: bool
    weight: int
    earned: int
    detail: str


def check_hsts(value: str) -> tuple[bool, str]:
    lowered = value.lower()
    if "max-age" not in lowered:
        return False, "Present but carries no max-age, so it does nothing"
    try:
        raw = lowered.split("max-age=", 1)[1].split(";")[0].strip()
        seconds = int(raw)
    except (IndexError, ValueError):
        return False, "Present but max-age is not a number"
    if seconds < 15_552_000:
        return False, f"max-age is only {seconds}s, below the recommended 15552000s (180 days)"
    if "includesubdomains" not in lowered:
        return True, f"max-age={seconds}s, though includeSubDomains is missing"
    return True, f"max-age={seconds}s with includeSubDomains"


def check_csp(value: str) -> tuple[bool, str]:
    lowered = value.lower()
    if "unsafe-inline" in lowered and "unsafe-eval" in lowered:
        return False, "Allows both unsafe-inline and unsafe-eval, which defeats the policy"
    if "unsafe-inline" in lowered:
        return False, "Allows unsafe-inline, so injected scripts still run"
    if "default-src" not in lowered and "script-src" not in lowered:
        return False, "No default-src or script-src, so scripts are unrestricted"
    return True, "Restricts sources without unsafe-inline"


def check_frame_options(value: str) -> tuple[bool, str]:
    normalised = value.strip().upper()
    if normalised in {"DENY", "SAMEORIGIN"}:
        return True, f"Set to {normalised}"
    return False, f"Unexpected value {value!r}, expected DENY or SAMEORIGIN"


def check_content_type_options(value: str) -> tuple[bool, str]:
    if value.strip().lower() == "nosniff":
        return True, "Set to nosniff"
    return False, f"Unexpected value {value!r}, the only valid value is nosniff"


def check_referrer_policy(value: str) -> tuple[bool, str]:
    weak = {"unsafe-url", "no-referrer-when-downgrade", ""}
    if value.strip().lower() in weak:
        return False, f"{value!r} still leaks the full URL to other origins"
    return True, f"Set to {value.strip()}"


CHECKS: tuple[Check, ...] = (
    Check(
        header="Strict-Transport-Security",
        weight=25,
        summary="Forces HTTPS for future visits",
        exposure="A first visit over HTTP can be intercepted and downgraded",
        validate=check_hsts,
    ),
    Check(
        header="Content-Security-Policy",
        weight=25,
        summary="Restricts where scripts and other resources may load from",
        exposure="An injected script runs with the full privileges of the page",
        validate=check_csp,
    ),
    Check(
        header="X-Frame-Options",
        weight=15,
        summary="Stops the page being framed by another site",
        exposure="The page can be framed invisibly and clicks hijacked",
        validate=check_frame_options,
    ),
    Check(
        header="X-Content-Type-Options",
        weight=15,
        summary="Stops the browser guessing content types",
        exposure="An uploaded file can be re-interpreted as a script",
        validate=check_content_type_options,
    ),
    Check(
        header="Referrer-Policy",
        weight=10,
        summary="Controls how much of the URL is sent to other sites",
        exposure="Full URLs, including tokens in query strings, leak to third parties",
        validate=check_referrer_policy,
    ),
    Check(
        header="Permissions-Policy",
        weight=10,
        summary="Disables browser features the page does not use",
        exposure="Embedded content can reach the camera, microphone or location",
    ),
)

TOTAL_WEIGHT = sum(check.weight for check in CHECKS)

GRADE_THRESHOLDS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (40, "E"))


class AuditError(RuntimeError):
    """Raised when a URL cannot be fetched."""


def normalise_url(target: str) -> str:
    if "://" not in target:
        return f"https://{target}"
    return target


def fetch_headers(
    url: str, *, timeout: float, insecure: bool, follow: bool
) -> tuple[dict[str, str], int, str]:
    """Fetch a URL and return its headers, status code and final URL."""
    seen: set[str] = set()
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        if current in seen:
            raise AuditError(f"Redirect loop at {current}")
        seen.add(current)

        parsed = urlparse(current)
        if parsed.scheme not in ("http", "https"):
            raise AuditError(f"Unsupported scheme {parsed.scheme!r}")
        if not parsed.hostname:
            raise AuditError(f"No hostname in {current!r}")

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        try:
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                if insecure:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                connection = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port or 443, timeout=timeout, context=context
                )
            else:
                connection = http.client.HTTPConnection(
                    parsed.hostname, parsed.port or 80, timeout=timeout
                )

            try:
                connection.request("GET", path, headers={"User-Agent": USER_AGENT})
                response = connection.getresponse()
                headers = dict(response.getheaders())
                status = response.status
                location = response.getheader("Location")
                response.read()
            finally:
                connection.close()
        except ssl.SSLError as exc:
            raise AuditError(f"TLS handshake failed: {exc}") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise AuditError(f"Request failed: {exc}") from exc

        if follow and status in (301, 302, 303, 307, 308) and location:
            current = location if "://" in location else f"{parsed.scheme}://{parsed.netloc}{location}"
            continue

        return headers, status, current

    raise AuditError(f"More than {MAX_REDIRECTS} redirects")


def lookup(headers: dict[str, str], name: str) -> str | None:
    """Header names are case insensitive, so compare them that way."""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def audit_headers(headers: dict[str, str], *, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []

    for check in CHECKS:
        value = lookup(headers, check.header)

        if check.header == "Strict-Transport-Security" and not is_https:
            findings.append(
                Finding(
                    header=check.header,
                    present=value is not None,
                    value=value,
                    passed=False,
                    weight=check.weight,
                    earned=0,
                    detail="Served over plain HTTP, so HSTS cannot protect this response",
                )
            )
            continue

        if value is None:
            findings.append(
                Finding(
                    header=check.header,
                    present=False,
                    value=None,
                    passed=False,
                    weight=check.weight,
                    earned=0,
                    detail=f"Missing. {check.exposure}",
                )
            )
            continue

        if check.validate is None:
            findings.append(
                Finding(
                    header=check.header,
                    present=True,
                    value=value,
                    passed=True,
                    weight=check.weight,
                    earned=check.weight,
                    detail="Present",
                )
            )
            continue

        passed, detail = check.validate(value)
        # A header that is present but weak still earns partial credit: it is
        # better than nothing, and the report says exactly what to fix.
        earned = check.weight if passed else check.weight // 2
        findings.append(
            Finding(
                header=check.header,
                present=True,
                value=value,
                passed=passed,
                weight=check.weight,
                earned=earned,
                detail=detail,
            )
        )

    return findings


def score(findings: Sequence[Finding]) -> int:
    earned = sum(finding.earned for finding in findings)
    return round(earned * 100 / TOTAL_WEIGHT)


def grade(percentage: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if percentage >= threshold:
            return letter
    return "F"


def find_disclosures(headers: dict[str, str]) -> list[tuple[str, str]]:
    disclosures = []
    for name in DISCLOSURE_HEADERS:
        value = lookup(headers, name)
        if value:
            disclosures.append((name, value))
    return disclosures


def print_report(
    url: str,
    status: int,
    findings: Sequence[Finding],
    disclosures: Sequence[tuple[str, str]],
) -> None:
    percentage = score(findings)
    letter = grade(percentage)

    print(f"\nSecurity header audit: {url}")
    print("=" * 68)
    print(f"HTTP status: {status}")
    print(f"Grade: {letter}  ({percentage}/100)\n")

    for finding in findings:
        if finding.passed:
            mark = "[+]"
        elif finding.present:
            mark = "[~]"
        else:
            mark = "[-]"
        print(f"{mark} {finding.header}")
        print(f"    {finding.detail}")
        if finding.value and finding.header != "Content-Security-Policy":
            print(f"    Value: {finding.value[:100]}")
        print()

    if disclosures:
        print("Information disclosure:")
        for name, value in disclosures:
            print(f"    {name}: {value}")
        print()

    failed = [finding for finding in findings if not finding.passed]
    if failed:
        print(f"{len(failed)} of {len(findings)} checks need attention.")
    else:
        print("All checks passed.")


def build_report(
    url: str,
    status: int,
    findings: Sequence[Finding],
    disclosures: Sequence[tuple[str, str]],
) -> dict:
    percentage = score(findings)
    return {
        "url": url,
        "status": status,
        "score": percentage,
        "grade": grade(percentage),
        "checks": [
            {
                "header": finding.header,
                "present": finding.present,
                "passed": finding.passed,
                "value": finding.value,
                "detail": finding.detail,
            }
            for finding in findings
        ],
        "information_disclosure": dict(disclosures),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Grade the HTTP security headers a site sends",
        epilog="Only audit sites you own or are authorised to test.",
    )
    parser.add_argument("url", help="Target URL, https:// is assumed when no scheme is given")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Skip certificate verification")
    parser.add_argument("--no-follow", action="store_true", help="Do not follow redirects")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--fail-under",
        type=int,
        metavar="SCORE",
        help="Exit with code 1 when the score is below this value",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.timeout <= 0:
        print("[!] --timeout must be greater than 0.", file=sys.stderr)
        return 2
    if args.fail_under is not None and not 0 <= args.fail_under <= 100:
        print("[!] --fail-under must be between 0 and 100.", file=sys.stderr)
        return 2

    url = normalise_url(args.url)

    try:
        headers, status, final_url = fetch_headers(
            url, timeout=args.timeout, insecure=args.insecure, follow=not args.no_follow
        )
    except AuditError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    findings = audit_headers(headers, is_https=final_url.startswith("https://"))
    disclosures = find_disclosures(headers)

    if args.json:
        print(json.dumps(build_report(final_url, status, findings, disclosures), indent=2))
    else:
        print_report(final_url, status, findings, disclosures)

    if args.fail_under is not None and score(findings) < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
