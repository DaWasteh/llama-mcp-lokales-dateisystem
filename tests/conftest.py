"""
Pytest-Konfiguration und gemeinsame Fixtures für alle Tests.
"""

import logging
import os
import sys

import pytest

# Projektroot in sys.path aufnehmen
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MCP-Server-Logging im Test-Betrieb unterdrücken
logging.getLogger("lokales_dateisystem").setLevel(logging.CRITICAL)
logging.getLogger("internet_recherche").setLevel(logging.CRITICAL)
logging.getLogger("mcp").setLevel(logging.CRITICAL)


@pytest.fixture()
def tmp_workdir(tmp_path):
    """Temporäres Arbeitsverzeichnis mit einigen Beispieldateien."""
    (tmp_path / "hello.txt").write_text("hello world", encoding="utf-8")
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02\x03")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def empty_dir(tmp_path):
    """Leeres temporäres Verzeichnis."""
    d = tmp_path / "empty"
    d.mkdir()
    return d
