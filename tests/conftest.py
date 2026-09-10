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
