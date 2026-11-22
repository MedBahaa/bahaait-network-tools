import os
import sys

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from utils.updater import CURRENT_VERSION, UpdateAvailableDialog, markdown_to_quantum_html


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


class TestUpdaterDialog:
    def test_markdown_to_quantum_html_formatting_and_escaping(self):
        sample = (
            "# BahaaIT v3.6.0\n"
            "## Major Features\n"
            "1. **Network Topology** (`topology_view.py`)\n"
            "- Supports *LLDP* and <script>alert(1)</script>\n"
            "  - Sub-item bullet\n"
        )
        rendered = markdown_to_quantum_html(sample)
        assert "<script>" not in rendered
        assert "&lt;script&gt;" in rendered
        assert "<h2 " in rendered and "<h3 " in rendered
        assert "<strong " in rendered and "Network Topology" in rendered
        assert "<code " in rendered and "topology_view.py" in rendered
        assert "<ol " in rendered and "<ul " in rendered

    def test_update_available_dialog_fixed_dimensions_and_scrollable_notes(self, qapp):
        rn_path = os.path.join(ROOT_DIR, "RELEASE_NOTES_v3.6.0.md")
        notes = open(rn_path, "r", encoding="utf-8").read()

        dlg = UpdateAvailableDialog(
            current_version="v3.5.0",
            latest_version=CURRENT_VERSION,
            release_notes=notes,
            download_url="https://github.com/MedBahaa/bahaait-network-tools/releases/tag/v3.6.0",
            has_installer=True,
        )
        try:
            dlg.show()
            qapp.processEvents()

            # Bounded responsive sizing regardless of release notes length
            assert 480 <= dlg.width() <= 820
            assert 420 <= dlg.height() <= 680

            # Long Markdown notes trigger clean vertical scrolling inside the QTextBrowser
            sb = dlg.notes_browser.verticalScrollBar()
            assert sb.maximum() > 0

            # Action buttons remain visible and strictly inside the dialog viewport
            for btn in (dlg.update_btn, dlg.later_btn, dlg.github_btn):
                assert btn.isVisible()
                bottom_y = btn.mapTo(dlg, btn.rect().bottomLeft()).y()
                assert bottom_y <= dlg.height()

            # Clean rendered text (no raw Markdown heading hashes or bold double-asterisks)
            plain = dlg.notes_browser.toPlainText()
            assert "BahaaIT Network Tools v3.6.0" in plain
            assert "## " not in plain
            assert "**" not in plain
        finally:
            dlg.close()
