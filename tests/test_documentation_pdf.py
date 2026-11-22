import base64
from pathlib import Path
import re
import sys
import zlib

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
DOCS_DIR = ROOT_DIR / "docs"
for p in (str(SRC_DIR), str(DOCS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from generate_documentation_pdf import generate_documentation_pdf, load_repo_metadata
from utils.updater import CURRENT_VERSION


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decode ReportLab ASCII85Decode/FlateDecode streams to inspect embedded PDF text."""
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)(?:\r?\n)?endstream", pdf_bytes, re.DOTALL):
        raw = match.group(1)
        decoded = raw
        if decoded.rstrip().endswith(b"~>"):
            try:
                decoded = base64.a85decode(decoded, adobe=True)
            except Exception:
                try:
                    decoded = base64.a85decode(decoded.rstrip()[:-2])
                except Exception:
                    pass
        try:
            decoded = zlib.decompress(decoded)
        except Exception:
            pass
        chunks.append(decoded.decode("latin-1", errors="ignore"))
    chunks.append(pdf_bytes.decode("latin-1", errors="ignore"))
    return "\n".join(chunks)


def test_documentation_metadata_matches_codebase():
    meta = load_repo_metadata()
    assert meta["version"] == CURRENT_VERSION
    assert meta["table_count"] == 28
    assert meta["en_keys"] == meta["fr_keys"]
    assert meta["fr_keys"] >= 862


def test_generate_documentation_pdf_valid_and_complete(tmp_path):
    target_pdf = tmp_path / "BahaaIT_Doc_Test.pdf"
    generated = generate_documentation_pdf(target_pdf)

    assert generated.exists()
    pdf_bytes = generated.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 25_000

    # Compter uniquement les objets Page (et non /Type /Pages)
    page_count = len(re.findall(rb"/Type\s*/Page(?![sA-Za-z])", pdf_bytes))
    assert page_count >= 8

    extracted = _extract_pdf_text(pdf_bytes)
    for expected in (
        CURRENT_VERSION,
        "BahaaIT Network Tools",
        "Infrastructure SNMP",
        "Moniteur Syslog",
        "Intelligence",
        "Topologie",
        "Inventaire",
        "VLAN",
        "Sauvegardes",
        "Audit",
        "Journal des Versions",
    ):
        assert expected in extracted, f"Chaine attendue absente du PDF: {expected!r}"

    # Verifier qu'aucun gabarit f-string n'a ete oublie
    for forbidden in ("{code_tag", "{meta", "{esc"):
        assert forbidden not in extracted, f"Placeholder non evalue detecte dans le PDF: {forbidden!r}"
