"""The inspection engine behind the WAF: signatures, scoring and rate limiting.

Kept separate from the proxy so it can be tested without a socket. A request is
reduced to a small `Request` object, run past a set of signatures, and either
allowed or blocked. A per-client rate limiter sits alongside.

The honest lesson this project teaches is in the design notes: signature
matching is a losing game against a determined attacker. It stops noise and
known payloads, not a creative adversary.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import unquote


@dataclass
class Request:
    """The parts of an HTTP request the engine inspects."""

    method: str
    path: str
    query: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    client_ip: str = "0.0.0.0"

    def inspectable_text(self) -> str:
        """Everything an attacker controls, decoded, joined for scanning.

        The path, query and body are URL-decoded twice, because a payload is
        often encoded once to pass through the browser and again to slip past a
        filter that decodes only once.
        """
        parts = [self.path, self.query, self.body]
        parts.extend(self.headers.get(name, "") for name in ("User-Agent", "Referer", "Cookie"))
        combined = " ".join(part for part in parts if part)
        once = unquote(combined)
        twice = unquote(once)
        return f"{combined} {once} {twice}"


@dataclass
class Signature:
    name: str
    category: str
    pattern: re.Pattern
    severity: int  # points added to the request's score


@dataclass
class Detection:
    signature: str
    category: str
    severity: int


@dataclass
class Verdict:
    allowed: bool
    score: int
    detections: list[Detection] = field(default_factory=list)
    reason: str = ""


def _sig(name: str, category: str, pattern: str, severity: int) -> Signature:
    return Signature(name, category, re.compile(pattern, re.IGNORECASE), severity)


# The signature set. Severity is points; a request is blocked once its total
# crosses the threshold, so one strong signal or several weak ones can block.
SIGNATURES: tuple[Signature, ...] = (
    _sig("sqli-union", "sql-injection", r"union\s+(all\s+)?select", 5),
    _sig("sqli-or-true", "sql-injection", r"'\s*or\s+'?\d+'?\s*=\s*'?\d+", 5),
    _sig("sqli-comment", "sql-injection", r"(--|#|/\*)\s*$", 2),
    _sig("sqli-stacked", "sql-injection", r";\s*(drop|delete|insert|update)\s", 5),
    _sig("sqli-sleep", "sql-injection", r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", 5),
    _sig("xss-script", "xss", r"<\s*script", 5),
    _sig("xss-event", "xss", r"\bon(error|load|click|mouseover)\s*=", 4),
    _sig("xss-javascript-uri", "xss", r"javascript:\s*\w", 5),
    _sig("xss-img-onerror", "xss", r"<\s*img[^>]+onerror", 5),
    _sig("traversal-dotdot", "path-traversal", r"(\.\./|\.\.\\){2,}", 4),
    _sig("traversal-etc-passwd", "path-traversal", r"/etc/passwd", 5),
    _sig("traversal-win-ini", "path-traversal", r"\\windows\\win\.ini", 5),
    _sig("cmdi-chain", "command-injection", r";\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", 5),
    _sig("cmdi-backtick", "command-injection", r"`[^`]+`", 3),
    _sig("cmdi-pipe", "command-injection", r"\|\s*(cat|nc|bash|sh|python)\b", 4),
    _sig("scanner-agent", "reconnaissance", r"\b(sqlmap|nikto|nmap|masscan|acunetix)\b", 3),
)

DEFAULT_THRESHOLD = 5


class RateLimiter:
    """A sliding-window rate limiter, one window per client address."""

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, client_ip: str, *, now: float | None = None) -> bool:
        """Record a request and return True if the client is within its limit."""
        current = time.monotonic() if now is None else now
        window = self._hits[client_ip]

        # Drop timestamps that have fallen out of the window.
        cutoff = current - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        window.append(current)
        return len(window) <= self.max_requests

    def reset(self, client_ip: str | None = None) -> None:
        if client_ip is None:
            self._hits.clear()
        else:
            self._hits.pop(client_ip, None)


def inspect(request: Request, *, threshold: int = DEFAULT_THRESHOLD) -> Verdict:
    """Run a request past every signature and decide whether to block it."""
    text = request.inspectable_text()
    detections: list[Detection] = []
    score = 0

    for signature in SIGNATURES:
        if signature.pattern.search(text):
            detections.append(
                Detection(
                    signature=signature.name,
                    category=signature.category,
                    severity=signature.severity,
                )
            )
            score += signature.severity

    if score >= threshold:
        categories = sorted({detection.category for detection in detections})
        return Verdict(
            allowed=False,
            score=score,
            detections=detections,
            reason=f"Blocked: {', '.join(categories)} (score {score} >= {threshold})",
        )

    return Verdict(allowed=True, score=score, detections=detections, reason="Allowed")
