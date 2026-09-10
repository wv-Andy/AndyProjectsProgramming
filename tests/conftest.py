"""Load the standalone project scripts as importable modules for the tests.

The projects are plain scripts rather than an installable package, so each one
is loaded from its path instead of imported by name.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Make the tests directory importable, so one test module can reuse another's
# packet-building helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load_module(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def scanner():
    return load_module("scanner", "Cybersecurity/async-port-scanner/scanner.py")


@pytest.fixture(scope="session")
def enumerator():
    return load_module("enumerator", "Cybersecurity/service-enumerator/enumerator.py")


@pytest.fixture(scope="session")
def x509():
    return load_module("x509", "Cybersecurity/tls-inspector/x509.py")


@pytest.fixture(scope="session")
def tls_inspector(x509):
    # inspector imports x509, so that module is loaded first.
    return load_module("inspector", "Cybersecurity/tls-inspector/inspector.py")


@pytest.fixture(scope="session")
def header_auditor():
    return load_module("header_auditor", "Cybersecurity/header-auditor/auditor.py")


@pytest.fixture(scope="session")
def subnetcalc():
    return load_module("subnetcalc", "Networking/subnet-calculator/subnetcalc.py")


@pytest.fixture(scope="session")
def log_analyzer():
    return load_module("log_analyzer", "Cybersecurity/log-analyzer/analyzer.py")


@pytest.fixture(scope="session")
def dnsproto():
    return load_module("dnsproto", "Networking/dns-enum/dnsproto.py")


@pytest.fixture(scope="session")
def dnsenum(dnsproto):
    # dnsenum imports dnsproto, so that module is loaded first.
    return load_module("dnsenum", "Networking/dns-enum/dnsenum.py")


@pytest.fixture(scope="session")
def decode():
    return load_module("decode", "Networking/packet-sniffer/decode.py")


@pytest.fixture(scope="session")
def sniffer(decode):
    # sniffer imports decode, so that module is loaded first.
    return load_module("sniffer", "Networking/packet-sniffer/sniffer.py")


@pytest.fixture(scope="session")
def pwaudit():
    return load_module("pwaudit", "Cybersecurity/password-auditor/pwaudit.py")


@pytest.fixture(scope="session")
def fim():
    return load_module("fim", "Cybersecurity/integrity-monitor/fim.py")


@pytest.fixture(scope="session")
def vulndb():
    return load_module("vulndb", "Cybersecurity/vuln-scanner/vulndb.py")


@pytest.fixture(scope="session")
def waf_engine():
    return load_module("engine", "Cybersecurity/mini-waf/engine.py")


@pytest.fixture(scope="session")
def crypto():
    return load_module("crypto", "Cybersecurity/secure-chat/crypto.py")


@pytest.fixture(scope="session")
def protocol(crypto):
    # protocol imports crypto, so that module is loaded first.
    return load_module("protocol", "Cybersecurity/secure-chat/protocol.py")


@pytest.fixture(scope="session")
def file_organizer():
    return load_module("organize", "PythonProjects/file-organizer/organize.py")


@pytest.fixture(scope="session")
def md2html():
    return load_module("md2html", "PythonProjects/markdown-converter/md2html.py")


@pytest.fixture(scope="session")
def task_manager():
    return load_module("tasks", "PythonProjects/task-manager/tasks.py")


@pytest.fixture(scope="session")
def web_scraper():
    return load_module("scraper", "PythonProjects/web-scraper/scraper.py")


@pytest.fixture(scope="session")
def kvstore():
    return load_module("kvstore", "PythonProjects/kv-database/kvstore.py")
