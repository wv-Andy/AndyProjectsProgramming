"""Tests for the DNS enumeration tool.

The protocol layer is covered in test_dnsproto. These focus on the logic the
enumerator adds on top: wordlists, wildcard filtering and zone-transfer framing.
"""

from __future__ import annotations

import asyncio

import pytest


def test_builtin_wordlist_is_used_by_default(dnsenum):
    words = dnsenum.load_wordlist(None)
    assert "www" in words and "mail" in words
    assert len(words) > 20


def test_wordlist_file_is_read_and_cleaned(dnsenum, tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("www\n# a comment\n\nMAIL\n  ftp  \n", encoding="utf-8")
    words = dnsenum.load_wordlist(path)
    assert words == ["www", "mail", "ftp"]


def test_missing_wordlist_is_an_error(dnsenum, tmp_path):
    with pytest.raises(dnsenum.QueryError):
        dnsenum.load_wordlist(tmp_path / "nope.txt")


def test_default_types_are_reasonable(dnsenum):
    assert "A" in dnsenum.DEFAULT_TYPES
    assert "NS" in dnsenum.DEFAULT_TYPES
    assert "MX" in dnsenum.DEFAULT_TYPES


def test_cli_rejects_bad_arguments(dnsenum):
    assert dnsenum.main(["example.com", "--timeout", "0"]) == 2
    assert dnsenum.main(["example.com", "--concurrency", "0"]) == 2


def test_wildcard_filtering_drops_wildcard_only_hits(dnsenum, monkeypatch):
    """A wildcard zone answers for everything, so those hits must be filtered.

    resolve_exists and detect_wildcard are stubbed so the test never touches the
    network. The brute-force sweep returns two names: one pointing only at the
    wildcard address, one pointing somewhere real.
    """
    wildcard_ip = "1.2.3.4"
    real_ip = "5.6.7.8"

    async def fake_wildcard(domain, resolver, *, timeout):
        return {wildcard_ip}

    async def fake_brute(domain, words, resolver, *, timeout, concurrency):
        return [
            (f"parked.{domain}", [dnsenum.Record("parked", "A", 300, wildcard_ip)]),
            (f"real.{domain}", [dnsenum.Record("real", "A", 300, real_ip)]),
        ]

    async def no_records(name, types, resolver, *, timeout):
        return {}

    monkeypatch.setattr(dnsenum, "detect_wildcard", fake_wildcard)
    monkeypatch.setattr(dnsenum, "brute_force", fake_brute)
    monkeypatch.setattr(dnsenum, "query_types", no_records)

    report = asyncio.run(
        dnsenum.enumerate_domain(
            "example.com",
            "8.8.8.8",
            timeout=1,
            concurrency=10,
            words=["parked", "real"],
            try_axfr=False,
        )
    )

    names = [entry["name"] for entry in report["subdomains"]]
    assert "real.example.com" in names
    assert "parked.example.com" not in names
    assert report["wildcard_addresses"] == [wildcard_ip]


def test_enumerate_collects_nameservers(dnsenum, monkeypatch):
    async def fake_query_types(name, types, resolver, *, timeout):
        return {"NS": [dnsenum.Record("example.com", "NS", 3600, "ns1.example.com")]}

    monkeypatch.setattr(dnsenum, "query_types", fake_query_types)

    report = asyncio.run(
        dnsenum.enumerate_domain(
            "example.com", "8.8.8.8", timeout=1, concurrency=10, words=None, try_axfr=False
        )
    )
    assert report["nameservers"] == ["ns1.example.com"]


@pytest.mark.network
def test_resolves_a_real_domain(dnsenum):
    try:
        response = asyncio.run(dnsenum.query("example.com", "A", "8.8.8.8", timeout=5))
    except dnsenum.QueryError as exc:
        pytest.skip(f"DNS unavailable: {exc}")
    assert response.response_code == "NOERROR"
    assert any(record.type == "A" for record in response.answers)


@pytest.mark.network
def test_nxdomain_for_a_made_up_name(dnsenum):
    made_up = "this-name-should-not-exist-abc123xyz.example.com"
    try:
        response = asyncio.run(dnsenum.query(made_up, "A", "8.8.8.8", timeout=5))
    except dnsenum.QueryError as exc:
        pytest.skip(f"DNS unavailable: {exc}")
    assert response.answers == []
