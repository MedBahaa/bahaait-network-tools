#!/usr/bin/env python3
"""Generateur de documentation PDF officielle et vivante pour BahaaIT Network Tools.

Ce script construit `docs/Documentation_BahaaIT_Network_Tools.pdf` a partir des
donnees reelles du depot (version dans `src/utils/updater.py`, tables dans
`src/utils/db.py`, cles i18n dans `src/utils/i18n.py`, logo dans `src/assets/logo.png`).

Regenerer apres toute modification fonctionnelle :
    python docs/generate_documentation_pdf.py
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, List, Optional, Sequence, Union
from xml.sax.saxutils import escape as xml_escape

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String as DString
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Flowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Chemins et metadonnees dynamiques du depot
# ---------------------------------------------------------------------------
DOCS_DIR = Path(__file__).resolve().parent
REPO_ROOT = DOCS_DIR.parent
DEFAULT_OUTPUT_PDF = DOCS_DIR / "Documentation_BahaaIT_Network_Tools.pdf"
LOGO_PATH = REPO_ROOT / "src" / "assets" / "logo.png"

# Palette Quantum Midnight / Edition Corporate Claire
C_MIDNIGHT = colors.HexColor("#0F172A")
C_SLATE_DARK = colors.HexColor("#1E293B")
C_SLATE = colors.HexColor("#334155")
C_MUTED = colors.HexColor("#64748B")
C_LIGHT_BORDER = colors.HexColor("#CBD5E1")
C_GRID = colors.HexColor("#E2E8F0")
C_ROW_ALT = colors.HexColor("#F8FAFC")
C_INDIGO = colors.HexColor("#4F46E5")
C_INDIGO_LIGHT = colors.HexColor("#6366F1")
C_INDIGO_BG = colors.HexColor("#EEF2FF")
C_CYAN = colors.HexColor("#06B6D4")
C_CYAN_BG = colors.HexColor("#ECFEFF")
C_EMERALD = colors.HexColor("#10B981")
C_EMERALD_BG = colors.HexColor("#ECFDF5")
C_AMBER = colors.HexColor("#F59E0B")
C_AMBER_BG = colors.HexColor("#FFFBEB")
C_ROSE = colors.HexColor("#F43F5E")
C_ROSE_BG = colors.HexColor("#FFF1F2")
C_WHITE = colors.white

# Largeur utile exacte sur A4 (595.27 - 42 - 42 = 511.27 pt -> 510 pt)
PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN_LEFT = 42
MARGIN_RIGHT = 42
MARGIN_TOP = 58
MARGIN_BOTTOM = 52
CONTENT_WIDTH = 510.0


def _assert_winansi(text: str) -> str:
    """Garantit l'encodage WinAnsi/cp1252 (evite les carres noirs dans Helvetica)."""
    try:
        text.encode("cp1252")
    except UnicodeEncodeError as exc:
        bad = text[exc.start:exc.end]
        raise ValueError(f"Caractere non supporte par WinAnsi/cp1252 detecte: {bad!r} dans {text!r}") from exc
    return text


def esc(text: str) -> str:
    """Echappe le texte brut pour ReportLab Paragraph apres controle cp1252."""
    return xml_escape(_assert_winansi(str(text)))


def load_repo_metadata() -> Dict[str, object]:
    """Lit version, nombre de tables SQLAlchemy et nombre de cles i18n sans effet de bord."""
    updater_path = REPO_ROOT / "src" / "utils" / "updater.py"
    db_path = REPO_ROOT / "src" / "utils" / "db.py"
    i18n_path = REPO_ROOT / "src" / "utils" / "i18n.py"

    version = "v3.5.0"
    if updater_path.exists():
        m = re.search(r'CURRENT_VERSION\s*=\s*["\']([^"\']+)["\']', updater_path.read_text(encoding="utf-8"))
        if m:
            version = m.group(1).strip()

    table_names: List[str] = []
    if db_path.exists():
        table_names = re.findall(r'__tablename__\s*=\s*["\']([^"\']+)["\']', db_path.read_text(encoding="utf-8"))

    en_count, fr_count = 862, 862
    if i18n_path.exists():
        tree = ast.parse(i18n_path.read_text(encoding="utf-8"), filename=str(i18n_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "translations" and isinstance(node.value, ast.Dict):
                        for k_node, v_node in zip(node.value.keys, node.value.values):
                            if isinstance(k_node, ast.Constant) and isinstance(v_node, ast.Dict):
                                if k_node.value == "en":
                                    en_count = len(v_node.keys)
                                elif k_node.value == "fr":
                                    fr_count = len(v_node.keys)

    return {
        "version": version,
        "version_num": version.lstrip("vV"),
        "table_names": table_names,
        "table_count": len(table_names),
        "en_keys": en_count,
        "fr_keys": fr_count,
        "generated_date": datetime.now().strftime("%d/%m/%Y"),
        "generated_ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


# ---------------------------------------------------------------------------
# Canevas multipages avec en-tete / pied de page courants et Page X / Y
# ---------------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    """Dessine la pagination 'Page X / Y' et le bandeau courant a partir de la page 2."""

    def __init__(self, *args, **kwargs):
        self._doc_version = kwargs.pop("doc_version", "v3.5.0")
        self._doc_date = kwargs.pop("doc_date", "")
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[dict] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_chrome(total_pages)
            super().showPage()
        super().save()

    def _draw_chrome(self, total_pages: int) -> None:
        page_num = self.getPageNumber()
        self.saveState()
        if page_num == 1:
            # Pied de page sobre de couverture
            self.setStrokeColor(C_LIGHT_BORDER)
            self.setLineWidth(0.6)
            self.line(MARGIN_LEFT, 38, PAGE_WIDTH - MARGIN_RIGHT, 38)
            self.setFont("Helvetica", 8)
            self.setFillColor(C_MUTED)
            self.drawString(
                MARGIN_LEFT,
                24,
                _assert_winansi(
                    f"BahaaIT Network Tools {self._doc_version} — Documentation Officielle (Document Vivant)"
                ),
            )
            self.drawRightString(
                PAGE_WIDTH - MARGIN_RIGHT,
                24,
                _assert_winansi(f"Edition du {self._doc_date}  |  Page {page_num} / {total_pages}"),
            )
        else:
            # En-tete courant (pages 2..N)
            top_y = PAGE_HEIGHT - 36
            self.setFont("Helvetica-Bold", 8.5)
            self.setFillColor(C_SLATE_DARK)
            self.drawString(
                MARGIN_LEFT,
                top_y,
                _assert_winansi(f"BahaaIT Network Tools {self._doc_version}"),
            )
            self.setFont("Helvetica", 8)
            self.setFillColor(C_INDIGO)
            self.drawRightString(
                PAGE_WIDTH - MARGIN_RIGHT,
                top_y,
                _assert_winansi("Documentation Technique & Guide Utilisateur"),
            )
            self.setStrokeColor(C_INDIGO_LIGHT)
            self.setLineWidth(1.2)
            self.line(MARGIN_LEFT, top_y - 6, MARGIN_LEFT + 70, top_y - 6)
            self.setStrokeColor(C_LIGHT_BORDER)
            self.setLineWidth(0.5)
            self.line(MARGIN_LEFT + 70, top_y - 6, PAGE_WIDTH - MARGIN_RIGHT, top_y - 6)

            # Pied de page courant (pages 2..N)
            self.setStrokeColor(C_LIGHT_BORDER)
            self.setLineWidth(0.5)
            self.line(MARGIN_LEFT, 36, PAGE_WIDTH - MARGIN_RIGHT, 36)
            self.setFont("Helvetica", 7.8)
            self.setFillColor(C_MUTED)
            self.drawString(
                MARGIN_LEFT,
                22,
                _assert_winansi("BahaaIT Network Tools — Mise a jour continue a chaque evolution fonctionnelle"),
            )
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(C_SLATE)
            self.drawRightString(
                PAGE_WIDTH - MARGIN_RIGHT,
                22,
                _assert_winansi(f"Page {page_num} / {total_pages}"),
            )
        self.restoreState()


# ---------------------------------------------------------------------------
# Flowables & styles reutilisables
# ---------------------------------------------------------------------------
def build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "Body": ParagraphStyle(
            "DocBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.3,
            leading=13.2,
            textColor=C_SLATE,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        ),
        "BodyLeft": ParagraphStyle(
            "DocBodyLeft",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.3,
            leading=13.0,
            textColor=C_SLATE,
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "Bullet": ParagraphStyle(
            "DocBullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.1,
            leading=12.8,
            leftIndent=14,
            firstLineIndent=-9,
            textColor=C_SLATE,
            spaceAfter=3.2,
        ),
        "SubTitle": ParagraphStyle(
            "DocSubTitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=C_INDIGO,
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "SmallSubTitle": ParagraphStyle(
            "DocSmallSubTitle",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.8,
            leading=13,
            textColor=C_SLATE_DARK,
            spaceBefore=6,
            spaceAfter=2,
            keepWithNext=True,
        ),
        "TblHdr": ParagraphStyle(
            "DocTblHdr",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=10.5,
            textColor=C_WHITE,
            alignment=TA_LEFT,
        ),
        "TblHdrCenter": ParagraphStyle(
            "DocTblHdrCenter",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.3,
            leading=10.5,
            textColor=C_WHITE,
            alignment=TA_CENTER,
        ),
        "TblCell": ParagraphStyle(
            "DocTblCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.8,
            textColor=C_SLATE,
            alignment=TA_LEFT,
        ),
        "TblCellBold": ParagraphStyle(
            "DocTblCellBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.2,
            leading=10.8,
            textColor=C_SLATE_DARK,
            alignment=TA_LEFT,
        ),
        "TblCellCenter": ParagraphStyle(
            "DocTblCellCenter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10.8,
            textColor=C_SLATE,
            alignment=TA_CENTER,
        ),
        "CodeBlock": ParagraphStyle(
            "DocCodeBlock",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.8,
            leading=10.4,
            textColor=colors.HexColor("#E2E8F0"),
            alignment=TA_LEFT,
        ),
        "CalloutTitle": ParagraphStyle(
            "DocCalloutTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.2,
            leading=12,
            spaceAfter=2,
        ),
        "CalloutBody": ParagraphStyle(
            "DocCalloutBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.7,
            leading=12.0,
            textColor=C_SLATE,
        ),
    }


def p(text_markup: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_assert_winansi(text_markup), style)


def code_tag(text: str) -> str:
    return f"<font name='Courier' size='8.2' color='#312E81'>{esc(text)}</font>"


def bullet(text_markup: str, styles: Dict[str, ParagraphStyle]) -> Paragraph:
    return p(f"<font color='#4F46E5'><b>•</b></font>  {text_markup}", styles["Bullet"])


def section_banner(num: str, title: str, first_flowable: Optional[Flowable] = None) -> Flowable:
    """Cree un bandeau de chapitre moderne avec barre d'accent Indigo + filet Cyan."""
    num_lbl = Paragraph(
        _assert_winansi(f"<b>{esc(num)}</b>"),
        ParagraphStyle(
            "SecNum",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            textColor=C_WHITE,
            alignment=TA_CENTER,
        ),
    )
    title_lbl = Paragraph(
        _assert_winansi(f"<b>{esc(title)}</b>"),
        ParagraphStyle(
            "SecTit",
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=17,
            textColor=C_MIDNIGHT,
            alignment=TA_LEFT,
        ),
    )
    tbl = Table([[num_lbl, title_lbl]], colWidths=[34, CONTENT_WIDTH - 34])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), C_INDIGO),
                ("BACKGROUND", (1, 0), (1, 0), C_INDIGO_BG),
                ("LINEABOVE", (0, 0), (-1, 0), 0.5, C_LIGHT_BORDER),
                ("LINEBELOW", (0, 0), (0, 0), 2.0, C_CYAN),
                ("LINEBELOW", (1, 0), (1, 0), 2.0, C_INDIGO),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (0, 0), 4),
                ("RIGHTPADDING", (0, 0), (0, 0), 4),
                ("LEFTPADDING", (1, 0), (1, 0), 10),
                ("RIGHTPADDING", (1, 0), (1, 0), 10),
            ]
        )
    )
    items: List[Flowable] = [Spacer(1, 6), tbl, Spacer(1, 7)]
    if first_flowable is not None:
        items.append(first_flowable)
    return KeepTogether(items)


def subsection(code: str, title: str, styles: Dict[str, ParagraphStyle]) -> Paragraph:
    return p(f"<font color='#06B6D4'><b>{esc(code)}</b></font>  {esc(title)}", styles["SubTitle"])


def callout_box(
    title: str,
    body_markup: str,
    styles: Dict[str, ParagraphStyle],
    tone: str = "info",
) -> Table:
    """Encadre d'information, bonne pratique, avertissement ou securite."""
    palette = {
        "info": (C_INDIGO_BG, C_INDIGO, "#312E81"),
        "tip": (C_EMERALD_BG, C_EMERALD, "#065F46"),
        "warn": (C_AMBER_BG, C_AMBER, "#92400E"),
        "security": (C_ROSE_BG, C_ROSE, "#9F1239"),
    }
    bg_color, border_color, title_hex = palette.get(tone, palette["info"])
    t_style = ParagraphStyle(
        f"CT_{tone}",
        parent=styles["CalloutTitle"],
        textColor=colors.HexColor(title_hex),
    )
    tbl = Table(
        [[[p(esc(title), t_style), p(body_markup, styles["CalloutBody"])]]],
        colWidths=[CONTENT_WIDTH],
    )
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                ("LINEBEFORE", (0, 0), (0, -1), 4, border_color),
                ("BOX", (0, 0), (-1, -1), 0.5, C_GRID),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return tbl


def code_box(lines: Sequence[str], styles: Dict[str, ParagraphStyle]) -> Table:
    """Bloc arborescence / commandes sur fond Quantum Midnight."""
    joined = "<br/>".join(esc(line).replace(" ", "&nbsp;") for line in lines)
    tbl = Table([[p(joined, styles["CodeBlock"])]], colWidths=[CONTENT_WIDTH])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), C_MIDNIGHT),
                ("LINEBEFORE", (0, 0), (0, -1), 3, C_CYAN),
                ("BOX", (0, 0), (-1, -1), 0.5, C_SLATE),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 11),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return tbl


def styled_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    col_widths: Sequence[float],
    styles: Dict[str, ParagraphStyle],
    center_cols: Optional[Sequence[int]] = None,
    bold_first_col: bool = True,
    cell_pad: float = 4.5,
) -> Table:
    """Tableau structure aux couleurs BahaaIT avec repetition automatique de l'en-tete."""
    if sum(col_widths) > CONTENT_WIDTH + 0.5:
        raise ValueError(f"Largeur totale tableau ({sum(col_widths)}) > {CONTENT_WIDTH}")
    cset = set(center_cols or [])
    hdr_row = [
        p(esc(h), styles["TblHdrCenter"] if idx in cset else styles["TblHdr"])
        for idx, h in enumerate(headers)
    ]
    data: List[List[Paragraph]] = [hdr_row]
    for row in rows:
        cells: List[Paragraph] = []
        for idx, val in enumerate(row):
            if idx in cset:
                st = styles["TblCellCenter"]
            elif idx == 0 and bold_first_col:
                st = styles["TblCellBold"]
            else:
                st = styles["TblCell"]
            cells.append(p(str(val), st))
        data.append(cells)

    tbl = Table(data, colWidths=list(col_widths), repeatRows=1)
    ts = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), C_SLATE_DARK),
            ("LINEBELOW", (0, 0), (-1, 0), 1.5, C_INDIGO),
            ("GRID", (0, 0), (-1, -1), 0.45, C_LIGHT_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]
    )
    for r_idx in range(1, len(data)):
        bg = C_WHITE if r_idx % 2 == 1 else C_ROW_ALT
        ts.add("BACKGROUND", (0, r_idx), (-1, r_idx), bg)
        ts.add("TOPPADDING", (0, r_idx), (-1, r_idx), cell_pad)
        ts.add("BOTTOMPADDING", (0, r_idx), (-1, r_idx), cell_pad)
    tbl.setStyle(ts)
    return tbl


def build_architecture_diagram(meta: Dict[str, object]) -> Drawing:
    """Diagramme vectoriel 4 couches de l'architecture BahaaIT Network Tools."""
    w = CONTENT_WIDTH
    h = 228.0
    d = Drawing(w, h)
    d.add(Rect(0, 0, w, h, fillColor=C_ROW_ALT, strokeColor=C_LIGHT_BORDER, strokeWidth=0.8, rx=6, ry=6))

    d.add(
        DString(
            w / 2.0,
            h - 15,
            _assert_winansi(f"Architecture Logicielle en 4 Couches — BahaaIT Network Tools {meta['version']}"),
            fontName="Helvetica-Bold",
            fontSize=9.2,
            textAnchor="middle",
            fillColor=C_MIDNIGHT,
        )
    )

    layers = [
        (
            154,
            C_INDIGO,
            "1. Couche Presentation (PySide6 / Quantum Midnight)",
            "14 vues modulaires  |  Fiches Details (Ping & SNMP 10 onglets)  |  pyqtgraph  |  WebEngine  |  System Tray",
        ),
        (
            106,
            C_CYAN,
            "2. Couche Moteurs Asynchrones (asyncio / QThread)",
            "AsyncPingEngine  |  WANMonitor  |  AsyncSNMPEngine (6 profils)  |  SyslogServer (UDP)  |  Scanners & Speedtest",
        ),
        (
            58,
            C_EMERALD,
            "3. Couche Intelligence, Correlation & Alertes",
            "AnomalyDetector (z-score)  |  IntelligenceEngine (6 regles multi-sources)  |  IncidentManager  |  AlertManager",
        ),
        (
            10,
            C_SLATE_DARK,
            f"4. Couche Persistance, Securite & Rapports ({meta['table_count']} Tables)",
            "SQLite WAL (SQLAlchemy 2.0, retention & agregation)  |  Windows DPAPI Vault  |  Supabase Sync  |  ReportLab PDF",
        ),
    ]

    box_x = 12
    box_w = w - 24
    box_h = 38
    for idx, (y, accent, title, desc) in enumerate(layers):
        d.add(Rect(box_x, y, box_w, box_h, fillColor=C_WHITE, strokeColor=C_LIGHT_BORDER, strokeWidth=0.7, rx=5, ry=5))
        d.add(Rect(box_x, y, 6, box_h, fillColor=accent, strokeColor=None, rx=2, ry=2))
        d.add(
            DString(
                box_x + 15,
                y + 23,
                _assert_winansi(title),
                fontName="Helvetica-Bold",
                fontSize=8.6,
                fillColor=C_MIDNIGHT,
            )
        )
        d.add(
            DString(
                box_x + 15,
                y + 9,
                _assert_winansi(desc),
                fontName="Helvetica",
                fontSize=7.5,
                fillColor=C_SLATE,
            )
        )
        if idx < len(layers) - 1:
            mid_x = w / 2.0
            y_top = y
            y_bot = layers[idx + 1][0] + box_h
            d.add(Line(mid_x - 35, y_top, mid_x - 35, y_bot, strokeColor=C_INDIGO_LIGHT, strokeWidth=1.1))
            d.add(
                Polygon(
                    [mid_x - 35, y_bot, mid_x - 38.5, y_bot + 4.5, mid_x - 31.5, y_bot + 4.5],
                    fillColor=C_INDIGO_LIGHT,
                    strokeColor=None,
                )
            )
            d.add(Line(mid_x + 35, y_bot, mid_x + 35, y_top, strokeColor=C_CYAN, strokeWidth=1.1))
            d.add(
                Polygon(
                    [mid_x + 35, y_top, mid_x + 31.5, y_top - 4.5, mid_x + 38.5, y_top - 4.5],
                    fillColor=C_CYAN,
                    strokeColor=None,
                )
            )

    return d


# ---------------------------------------------------------------------------
# Construction des sections du document
# ---------------------------------------------------------------------------
def build_cover_page(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []

    # 1. Bloc Hero sombre Quantum Midnight avec logo, titre et badge version
    logo_flow: Union[Image, str] = ""
    if LOGO_PATH.exists():
        ir = ImageReader(str(LOGO_PATH))
        lw, lh = ir.getSize()
        target_h = 62.0
        target_w = target_h * (lw / lh) if lh else 71.0
        logo_flow = Image(str(LOGO_PATH), width=target_w, height=target_h)
        logo_flow.hAlign = "LEFT"

    version_badge = Paragraph(
        _assert_winansi(f"<b>VERSION {esc(str(meta['version']).upper())} — EDITION WINDOWS 64-BIT</b>"),
        ParagraphStyle(
            "CoverBadge",
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=C_CYAN,
            alignment=TA_LEFT,
        ),
    )
    hero_title = Paragraph(
        _assert_winansi("<b>Bahaa<font color='#818CF8'>IT</font> Network Tools</b>"),
        ParagraphStyle(
            "CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=32,
            textColor=C_WHITE,
            spaceAfter=4,
        ),
    )
    hero_sub = Paragraph(
        _assert_winansi(
            "Documentation Technique, Architecture & Guide Utilisateur Officiel"
        ),
        ParagraphStyle(
            "CoverSub",
            fontName="Helvetica",
            fontSize=12.5,
            leading=16,
            textColor=colors.HexColor("#CBD5E1"),
            spaceAfter=6,
        ),
    )
    hero_tagline = Paragraph(
        _assert_winansi(
            "Suite tout-en-un d'administration reseau, supervision ICMP/SNMP v1-v2c-v3, "
            "collecte Syslog, correlation intelligente et plateforme Infrastructure Management (v3.6.0)."
        ),
        ParagraphStyle(
            "CoverTagline",
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#94A3B8"),
        ),
    )

    top_row = Table(
        [[logo_flow, [version_badge, hero_title, hero_sub]]],
        colWidths=[84, CONTENT_WIDTH - 124],
    )
    top_row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    hero_card = Table(
        [[[top_row, Spacer(1, 6), hero_tagline]]],
        colWidths=[CONTENT_WIDTH],
    )
    hero_card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), C_MIDNIGHT),
                ("LINEABOVE", (0, 0), (-1, 0), 4, C_INDIGO),
                ("LINEBELOW", (0, 0), (-1, 0), 3, C_CYAN),
                ("TOPPADDING", (0, 0), (-1, -1), 26),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 24),
                ("LEFTPADDING", (0, 0), (-1, -1), 20),
                ("RIGHTPADDING", (0, 0), (-1, -1), 20),
            ]
        )
    )
    story.append(hero_card)
    story.append(Spacer(1, 18))

    # 2. Grille 4 KPI de couverture applicative
    kpis = [
        ("19", "Modules Applicatifs", "Supervision, Outils, Gestion, Infra, Systeme"),
        (str(meta["table_count"]), "Tables SQLite", "Mode WAL + triggers audit + retention"),
        ("6 / 12", "Profils & Categories", "6 profils SNMP + 12 categories Syslog"),
        (f"{meta['fr_keys']}", "Cles Bilingues", "Couverture 1:1 Francais / Anglais"),
    ]
    kpi_cells = []
    for big_val, lbl, sub in kpis:
        kpi_cells.append(
            [
                Paragraph(
                    _assert_winansi(f"<b>{esc(big_val)}</b>"),
                    ParagraphStyle("CKV", fontName="Helvetica-Bold", fontSize=18, leading=21, textColor=C_INDIGO, alignment=TA_CENTER),
                ),
                Paragraph(
                    _assert_winansi(f"<b>{esc(lbl)}</b>"),
                    ParagraphStyle("CKL", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=C_MIDNIGHT, alignment=TA_CENTER),
                ),
                Paragraph(
                    _assert_winansi(esc(sub)),
                    ParagraphStyle("CKS", fontName="Helvetica", fontSize=7.4, leading=9.5, textColor=C_MUTED, alignment=TA_CENTER),
                ),
            ]
        )
    kpi_tbl = Table([kpi_cells], colWidths=[CONTENT_WIDTH / 4.0] * 4)
    kpi_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), C_ROW_ALT),
                ("BOX", (0, 0), (-1, -1), 0.7, C_LIGHT_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.7, C_LIGHT_BORDER),
                ("LINEABOVE", (0, 0), (-1, 0), 2.5, C_INDIGO),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(kpi_tbl)
    story.append(Spacer(1, 18))

    # 3. Objet du document
    story.append(
        p(
            "<b>Objet du document :</b> Cette documentation constitue le referentiel technique et "
            "fonctionnel de l'application <b>BahaaIT Network Tools</b>. Elle decrit l'architecture logicielle, "
            "les mecanismes de securite, chacun des <b>19 modules de l'interface Quantum Midnight</b>, le modele "
            f"relationnel SQLite ({meta['table_count']} tables) et la politique de maintenance continue garantissant que ce manuel evolue en "
            "parallele de chaque nouvelle fonctionnalite.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 10))

    # 4. Tableau de controle documentaire
    ctrl_rows = [
        ["Application", "BahaaIT Network Tools (Suite reseau, supervision NOC & Infrastructure Management)"],
        ["Version logicielle", f"<b>{esc(str(meta['version']))}</b> — Plateforme Infrastructure Management (Roadmap 01, 02 &amp; 03)"],
        ["Environnement cible", "Windows 10 / Windows 11 (64-bit) — Packaging PyInstaller &amp; Inno Setup"],
        ["Socle technologique", "Python 3.14, PySide6 (Qt 6 + WebEngine), SQLAlchemy 2.0 (SQLite WAL), pysnmp, Paramiko, pyqtgraph, ReportLab"],
        ["Securite des secrets", "Windows DPAPI (crypt32.dll) + masquage automatique des communautes/mots de passe"],
        ["Date de generation", f"{esc(str(meta['generated_ts']))} (via {code_tag('docs/generate_documentation_pdf.py')})"],
        ["Statut documentaire", "<b>Document vivant</b> — Regle projet : mise a jour et regeneration PDF a chaque evolution"],
    ]
    story.append(
        styled_table(
            ["Attribut", "Detail de reference"],
            ctrl_rows,
            [145, CONTENT_WIDTH - 145],
            styles,
        )
    )
    story.append(Spacer(1, 14))
    story.append(
        callout_box(
            "Politique de Documentation Vivante (Mise a jour systematique)",
            f"Le script {code_tag('docs/generate_documentation_pdf.py')} lit dynamiquement la version active dans "
            f"{code_tag('src/utils/updater.py')}, le schema SQLite dans {code_tag('src/utils/db.py')} et les dictionnaires "
            f"i18n dans {code_tag('src/utils/i18n.py')}. Une regle permanente dans {code_tag('AGENTS.md')} impose de "
            "mettre a jour ce script et de regenerer le present PDF a chaque ajout ou modification fonctionnelle.",
            styles,
            tone="info",
        )
    )
    story.append(PageBreak())
    return story


def build_toc_and_overview(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "00",
            "Sommaire & Cartographie Rapide de l'Application",
            p(
                "Le tableau ci-dessous presente l'organisation complete de la documentation et permet d'identifier "
                "immediatement le chapitre correspondant a chaque composant technique ou ecran metier.",
                styles["Body"],
            ),
        )
    )
    toc_rows = [
        ["Chapitre 01", "Presentation Generale & Architecture Logicielle", "Vision, pile Python 3.14/PySide6, diagramme 4 couches, arborescence, demarrage et verrou d'instance."],
        ["Chapitre 02", "Installation, Privileges & Securite", "Windows 10/11, Npcap, UAC Admin vs non-Admin, stockage AppData, DPAPI, pare-feu Syslog, mises a jour OTA."],
        ["Chapitre 03", "Supervision & Intelligence Reseau (6 Modules)", "Dashboard 10 KPI/8 graphiques, Live Ping + WAN, SNMP Infrastructure (10 onglets), Syslog UDP, Intelligence, Global Status."],
        ["Chapitre 04", "Outils de Diagnostic & Performance (3 Modules)", "Scanners 5 modes (ARP, Ports, Tracert, Wi-Fi BSSID, Smart Diag), Boite a Outils 7 terminaux, Speedtest & PDF."],
        ["Chapitre 05", "Administration, Multi-Sites & Infrastructure Management (8 Modules)", "Web Manager, Centre d'Acces SSH strict/RDP, Multi-Sites, Topologie 4 modes, Inventaire 11 cat., VLANs, Sauvegardes DPAPI/Diff/Restauration, Audit."],
        ["Chapitre 06", "Configuration Systeme & Parametres (2 Modules)", "Configuration IPv4/DHCP Windows, Parametres Globaux 4 onglets (General, Alertes, Moteur Reseau, Cloud/Backup)."],
        ["Chapitre 07", f"Base de Donnees SQLite & Retention ({meta['table_count']} Tables)", "Mode WAL, migration non destructive v3.3->v3.4->v3.5->v3.6, catalogue des 28 tables, triggers immuabilite audit."],
        ["Chapitre 08", "Qualite, Benchmarks Mesures & Packaging", "Suites pytest (dont v3.6.0 securite & echelle 1000 equipements / 250 noeuds / 50 backups), PyInstaller & Inno Setup."],
        ["Chapitre 09", "Maintenance Continue & Journal des Versions", "Procedure de mise a jour automatique du PDF (AGENTS.md) et historique detaille v3.3.0 -> v3.6.0."],
    ]
    story.append(styled_table(["Section", "Intitule", "Contenu couvert"], toc_rows, [74, 182, CONTENT_WIDTH - 256], styles))
    story.append(Spacer(1, 10))

    story.append(subsection("0.1", "Index Complet des 19 Ecrans de Navigation (Barre Laterale)", styles))
    nav_rows = [
        ["Supervision", "0", "Tableau de Bord (Dashboard)", code_tag("dashboard_view.py"), "10 cartes KPI, 8 graphiques, inventaire SNMP, alertes & sites"],
        ["Supervision", "1", "Monitoring en Direct", code_tag("monitor_view.py"), "Ping asynchrone 4 etats, Incidents, Intelligence WAN, Retention"],
        ["Supervision", "11", "Infrastructure SNMP", code_tag("snmp_view.py"), "Decouverte SNMP v1/v2c/v3, 6 profils, fiche details 10 onglets"],
        ["Supervision", "12", "Moniteur Syslog", code_tag("syslog_view.py"), "Collecteur UDP 514/5514 RFC 3164/5424, 12 categories, exports"],
        ["Supervision", "13", "Intelligence Reseau", code_tag("intelligence_view.py"), "Anomalies statistiques + correlation 6 regles multi-sources"],
        ["Supervision", "9", "Etat des Services", code_tag("service_status_view.py"), "Acces direct statuts officiels Apple, Netflix, PlayStation"],
        ["Outils", "3", "Scanners Reseau", code_tag("scanner_view.py"), "LAN/ARP, Ports asyncio, Traceroute, Wi-Fi BSSID, Smart Diag"],
        ["Outils", "2", "Boite a Outils IT", code_tag("tools_view.py"), "7 outils en terminaux multi-onglets horodates + export .txt"],
        ["Outils", "6", "Test de Performance", code_tag("speedtest_view.py"), "Download, Upload, Ping, Jitter, Perte %, historique & PDF"],
        ["Gestion", "7", "Gestionnaire Web", code_tag("browser_view.py"), "Navigateur Chromium integre, plein ecran, tolerance TLS LAN"],
        ["Gestion", "8", "Centre d'Acces & Admin", code_tag("remote_view.py"), "Multi-sessions SSH strict known_hosts, CLI garde, RDP, Telnet/COM"],
        ["Gestion", "10", "Gestionnaire Multi-Sites", code_tag("sites_view.py"), "Hierarchie Org->Region->Site, KPIs, Ping, comparaison, CSV/PDF"],
        ["Infrastructure", "14", "Topologie Reseau", code_tag("topology_view.py"), "Decouverte LLDP/CDP/FDB/ARP/Route, carte QGraphicsView 4 modes"],
        ["Infrastructure", "15", "Inventaire Equipements", code_tag("inventory_view.py"), "11 categories, synchro SNMP/Hotes, doublons IP/MAC, garanties"],
        ["Infrastructure", "16", "Gestion des VLANs", code_tag("vlan_view.py"), "Matrice multi-switchs, incoherences, planification CLI confirmee"],
        ["Infrastructure", "17", "Sauvegardes & Diff", code_tag("backup_view.py"), "Sauvegardes DPAPI+SHA-256, Diff visuel, modeles & restauration"],
        ["Infrastructure", "18", "Journal d'Audit", code_tag("audit_view.py"), "Journal immuable append-only avec verification SHA-256"],
        ["Systeme", "4", "Configuration Reseau", code_tag("config_view.py"), "Lecture/ecriture IPv4 statique, DNS, bascule DHCP via netsh"],
        ["Systeme", "5", "Parametres Globaux", code_tag("settings_view.py"), "Langue FR/EN, Ghost Mode, Audio/SMTP, Npcap, Cloud Sync/Backup"],
    ]
    story.append(
        styled_table(
            ["Groupe", "Idx", "Ecran", "Module UI", "Role principal"],
            nav_rows,
            [62, 26, 106, 124, CONTENT_WIDTH - 318],
            styles,
            center_cols=[1],
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_1(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "01",
            "Presentation Generale & Architecture Logicielle",
            p(
                "<b>BahaaIT Network Tools</b> est une suite bureau native concue pour les administrateurs reseau, "
                "ingenieurs systemes et equipes NOC/support sur <b>Windows 10 / 11 (64-bit)</b>. Elle unifie dans "
                "une interface sombre homogene (<b>Quantum Midnight UI</b>) la supervision active et passive, le "
                "diagnostic terrain, la gestion distante et le reporting client.",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("1.1", "Pile Technologique Verifiee (requirements.txt)", styles))
    stack_rows = [
        ["Runtime & Concurrence", "Python 3.14 (64-bit), asyncio, QThread", "Execution parallele non bloquante des sondes ICMP/SNMP/Syslog"],
        ["Interface Graphique", "PySide6, PySide6-WebEngine, pyqtgraph", "19 ecrans Qt 6 (Quantum Midnight v2), icones SVG natives, courbes haute frequence, navigateur Chromium integre"],
        ["Supervision SNMP", "pysnmp (v7), pysnmpcrypto, pyasn1", "Protocole SNMP v1, v2c et v3 complet (auth SHA-512, chiffrement AES-256)"],
        ["Moteurs Reseau & OS", "icmplib, scapy (Npcap), psutil, netsh", "Sondes ICMP asynchrones, decouverte ARP, metriques interface et Wi-Fi"],
        ["Administration Distante", "paramiko, pyserial, socket", "Terminaux interactifs SSH, Telnet et consoles Serie COM"],
        ["Base de Donnees", "SQLAlchemy 2.0 + SQLite (mode WAL)", f"{meta['table_count']} tables locales relationnelles, agregation et retention configurees"],
        ["Securite & Cloud", "Windows Crypt32 DPAPI, supabase, requests", "Protection locale des secrets, authentification cloud et verifications HTTP"],
        ["Reporting & Packaging", "ReportLab, PyInstaller (--onedir), Inno Setup", "Generation de rapports PDF Corporate et installateur Windows UAC"],
    ]
    story.append(styled_table(["Domaine", "Technologies", "Role dans BahaaIT"], stack_rows, [115, 165, CONTENT_WIDTH - 280], styles))
    story.append(Spacer(1, 10))

    story.append(subsection("1.2", "Architecture en 4 Couches & Cycle d'Execution", styles))
    story.append(build_architecture_diagram(meta))
    story.append(Spacer(1, 9))

    story.append(subsection("1.3", "Demarrage, En-tete Permanent & Fermeture Propre", styles))
    story.append(bullet(f"<b>Point d'entree ({code_tag('src/main.py')})</b> : configure l'identifiant barre des taches Windows ({code_tag('AppUserModelID')}), masque automatiquement les fenetres console des sous-processus Windows ({code_tag('CREATE_NO_WINDOW')}) et applique les options TLS WebEngine selon la configuration.", styles))
    story.append(bullet(f"<b>Verrou d'instance unique</b> : un serveur local Qt ({code_tag('QLocalServer')}) empeche le lancement de doublons et ramene la fenetre existante au premier plan si l'utilisateur relance l'executable.", styles))
    story.append(bullet("<b>En-tete global temps reel</b> : affiche en permanence le statut reseau actif (Wi-Fi + SSID + signal % ou Ethernet), le nom d'hote, l'IP locale et l'IP publique rafraichies toutes les 10 secondes dans un thread dedie.", styles))
    story.append(bullet(f"<b>Chargement optimise &amp; arret controle</b> : la fenetre sans bordure est librement redimensionnable (poignees, agrandissement/restauration, double-clic en-tete) et charge le Dashboard (index 0) immediatement, puis precharge les vues 1 a 18 en arriere-plan (file {code_tag('QTimer')}). A la fermeture ({code_tag('shutdown()')}), tous les moteurs (Ping, SNMP, Syslog, Scanners, Access, Topologie, Sauvegardes) sont arretes proprement et leurs tampons SQLite vides.", styles))

    story.append(subsection("1.4", "Structure Reelle du Projet", styles))
    story.append(
        code_box(
            [
                "BahaaIT/",
                "|-- assets/                 # Icones SVG, alarme audio (.wav), icone application (.ico)",
                "|-- build_scripts/          # build.py (PyInstaller --onedir) et setup_compiler.iss (Inno Setup)",
                "|-- docs/                   # generate_documentation_pdf.py + Documentation_BahaaIT_Network_Tools.pdf",
                "|-- src/",
                "|   |-- main.py             # Initialisation Qt, single-instance, file dialogs, theme sombre",
                "|   |-- assets/             # Logo BahaaIT (logo.png) et logos SVG de services",
                "|   |-- core/               # Moteurs metier: ping_engine, snmp_engine, snmp_client, snmp_profiles,",
                "|   |                       #   device_health, interface_monitor, poe_monitor, vlan_monitor,",
                "|   |                       #   syslog_server/parser/classifier, anomaly_detector, intelligence_engine,",
                "|   |                       #   monitor, monitoring_state/statistics, incident_manager, alert_manager,",
                "|   |                       #   wan_monitor, scanner, speedtest, tools, net_config, service_checker",
                "|   |-- ui/                 # main_window.py, styles.qss, system_tray.py + 21 widgets dans widgets/",
                "|   +-- utils/              # db.py, config.py, auth.py, snmp_credentials.py, i18n.py, pdf_generator.py,",
                "|                           #   monitoring_export.py, email_notifier.py, audio.py, admin.py, updater.py",
                "|-- tests/                  # 9 suites pytest couvrant fondations, UI, SNMP, Syslog, IA et documentation",
                "+-- AGENTS.md               # Regle permanente imposant la mise a jour du PDF a chaque evolution",
            ],
            styles,
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_2(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "02",
            "Installation, Privileges Systeme & Securite",
            p(
                "BahaaIT Network Tools interagit directement avec la pile reseau Windows et manipule des "
                "identifiants d'infrastructure critiques (SMTP, sessions cloud, communautes SNMPv2c et cles SNMPv3). "
                "L'architecture applique une defense en profondeur stricte.",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("2.1", "Prerequis & Gestion des Privileges (Admin vs Standard)", styles))
    priv_rows = [
        ["Edition d'IP statique / DHCP", code_tag("netsh interface ipv4"), "Administrateur requis", "Banniere UAC dans Configuration Reseau avec bouton d'elevation en 1 clic"],
        ["Scan LAN ARP rapide", "Scapy + pilote Npcap", "Npcap recommande", "Bascule automatique transparente vers scan ICMP multithread (30 workers) si absent"],
        ["Collecteur Syslog UDP", f"{code_tag('syslog_server.py')}", "Port 514 = Admin | 5514 = Standard", "Port configurable dans l'interface ; guide de commande pare-feu integre"],
        ["Requetes Ping & SNMP", "icmplib / pysnmp UDP 161", "Execution standard ou Admin", "Repli automatique sur utilitaire systeme sans blocage si socket brut indisponible"],
    ]
    story.append(styled_table(["Capacite", "Composant", "Exigence Windows", "Comportement de repli / protection"], priv_rows, [115, 110, 120, CONTENT_WIDTH - 345], styles))
    story.append(Spacer(1, 8))

    story.append(subsection("2.2", "Chiffrement Materiel Windows DPAPI & Masquage des Secrets", styles))
    story.append(bullet(f"<b>Vault Windows DPAPI 64-bit ({code_tag('utils/auth.py')}, {code_tag('utils/snmp_credentials.py')})</b> : les mots de passe SMTP, le jeton cloud {code_tag('session.dat')} et l'ensemble des secrets SNMP (communautes v1/v2c, cles d'authentification et de confidentialite SNMPv3) sont chiffres au repos via {code_tag('CryptProtectData')} ({code_tag('crypt32.dll')}) et lies cryptographiquement au compte Windows et a la machine locale.", styles))
    story.append(bullet("<b>Zero fuite de secrets (Secret Scrubbing)</b> : les objets credentials masquent automatiquement les champs sensibles dans leur representation texte, les erreurs SNMP, les journaux applicatifs, les instantanes diagnostiques et les tableaux de l'interface.", styles))
    story.append(bullet("<b>Persistance locale isolee</b> : la configuration et la base SQLite sont stockees dans le dossier utilisateur Windows dedie (acces direct depuis <i>Parametres &gt; Sauvegarde, Sync &amp; Stockage</i>).", styles))

    story.append(Spacer(1, 4))
    story.append(
        callout_box(
            "Ouverture du Pare-feu Windows pour la reception Syslog UDP",
            "Pour recevoir des journaux Syslog emis par des equipements externes (routeurs, switches, pare-feux), "
            f"autorisez le port UDP choisi (514 ou 5514) en PowerShell Administrateur :<br/>"
            f"{code_tag('New-NetFirewallRule -DisplayName \"BahaaIT Syslog UDP 514\" -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow')}",
            styles,
            tone="security",
        )
    )
    story.append(Spacer(1, 8))

    story.append(subsection("2.3", "Mises a Jour Automatiques (OTA GitHub Releases)", styles))
    story.append(
        p(
            f"Le module {code_tag('src/utils/updater.py')} compare periodiquement {code_tag('CURRENT_VERSION')} "
            f"(actuellement <b>{esc(str(meta['version']))}</b>) avec la derniere release publiee sur GitHub "
            f"({code_tag('MedBahaa/bahaait-network-tools')}). Lorsqu'une nouvelle version est disponible, la fenetre "
            f"<b>UpdateAvailableDialog</b> (dimensions bornees 660x560 px adaptatives) affiche les notes de version "
            f"formatees depuis le Markdown dans un panneau defilant ({code_tag('QTextBrowser')}), propose le lien GitHub "
            f"et telecharge l'installateur {code_tag('.exe')} avec suivi de progression.",
            styles["Body"],
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_3(styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "03",
            "Modules de Supervision & Intelligence Reseau (6 Modules)",
            p(
                "Le groupe <b>Supervision</b> reunit le pilotage centralise du parc : vision globale NOC, "
                "supervision ICMP continue avec hysteresis, telemetrie SNMP multi-constructeurs, collecte Syslog "
                "et moteur de correlation multi-sources.",
                styles["Body"],
            ),
        )
    )

    # 3.1 Dashboard
    story.append(subsection("3.1", "Tableau de Bord NOC (DashboardView — Index 0)", styles))
    story.append(
        p(
            f"Implemente dans {code_tag('src/ui/widgets/dashboard_view.py')}, le tableau de bord offre une synthese "
            "consolidee en temps reel de l'etat reseau, de l'infrastructure SNMP, des evenements Syslog et des anomalies actives :",
            styles["Body"],
        )
    )
    dash_rows = [
        ["Ligne 1 (5 cartes KPI)", "Hotes UP (UP/Total), Equipements SNMP, Interfaces UP/DOWN, Anomalies Actives, Alertes Syslog"],
        ["Ligne 2 (5 cartes KPI)", "CPU Moyen Infra (%), RAM Moyenne Infra (%), Utilisation PoE globale, Debit Download, Latence moyenne (ms)"],
        ["8 Graphiques Temps Reel", "Debit Reseau Live (BandwidthChart) ; Tendance CPU % ; Tendance RAM % ; Trafic Agrege Interfaces (In/Out Mbps) ; Top Interfaces Saturees (%) ; Repartition Sante SNMP ; Distribution Severites Syslog ; Anomalies par Type"],
        ["Tableaux de Synthese", "Inventaire Infrastructure SNMP (Nom, IP, Constructeur/Modele, Statut, CPU %, RAM %, Interfaces) + blocs Dernieres Alertes & Sites"],
    ]
    story.append(styled_table(["Zone du Dashboard", "Indicateurs et visualisations affiches"], dash_rows, [126, CONTENT_WIDTH - 126], styles, cell_pad=3.5))
    story.append(Spacer(1, 4))

    # 3.2 Live Monitoring
    story.append(subsection("3.2", "Monitoring en Direct & Intelligence WAN (MonitorView — Index 1)", styles))
    story.append(bullet(f"<b>Moteur asynchrone 100+ hotes ({code_tag('ping_engine.py')}, {code_tag('monitor.py')})</b> : sondes {code_tag('asyncio')} executees dans un {code_tag('QThread')} dedie avec classification stricte en 4 issues ({code_tag('SUCCESS')}, {code_tag('TIMEOUT')}, {code_tag('DNS_ERROR')}, {code_tag('ENGINE_ERROR')}). Les erreurs locales d'ordonnanceur n'alterent jamais les taux de perte.", styles))
    story.append(bullet(f"<b>Machine a 4 etats avec hysteresis ({code_tag('monitoring_state.py')})</b> : {code_tag('UP')} (nominal), {code_tag('DEGRADED')} (derive latence/jitter/perte ou N echecs partiels, defaut 3), {code_tag('DOWN')} (panne confirmee apres K echecs critiques, defaut 5), {code_tag('RECOVERING')} (stabilisation sur M succes consecutifs, defaut 3 avant retour UP), plus l'etat persiste {code_tag('PAUSED')}.", styles))
    story.append(bullet(f"<b>Statistiques & Fiche Hote ({code_tag('monitoring_statistics.py')}, {code_tag('host_details_view.py')})</b> : perte de paquets (%), gigue IPDV (ms), latence Min/Avg/Max/P95 et disponibilite (%) sur fenetres <b>1m, 5m, 15m, 1h et 24h</b> avec courbes {code_tag('pyqtgraph')}.", styles))
    story.append(bullet(f"<b>Centre d'Incidents ({code_tag('incident_center.py')})</b> : cycle complet {code_tag('DETECTED -> ACKNOWLEDGED -> RECOVERED -> CLOSED')}, filtres multi-criteres, acquittement technicien, <b>commentaires horodates</b>, cloture manuelle, suppression unitaire ou totale, export CSV et <b>Rapport PDF Corporate</b> incluant le journal complet des interventions.", styles))
    story.append(bullet(f"<b>Intelligence WAN ({code_tag('wan_monitor.py')})</b> : correlation autonome sur 5 cibles (Passerelle locale, {code_tag('8.8.8.8')}, {code_tag('1.1.1.1')}, Resolution DNS, HTTPS port 443) produisant 9 verdicts precis : {code_tag('HEALTHY')}, {code_tag('WAN_OUTAGE_CONFIRMED')}, {code_tag('WAN_OUTAGE_SUSPECTED')}, {code_tag('LAN_GATEWAY_ISSUE')}, {code_tag('DNS_FAILURE')}, {code_tag('ICMP_FILTERED_WAN_OK')}, {code_tag('HTTPS_BLOCKED_OR_PROXY')}, {code_tag('DESTINATION_ROUTING_ISSUE')} et {code_tag('GATEWAY_ICMP_BLOCKED')}.", styles))
    story.append(bullet(f"<b>Alertes Multi-Canaux Dedupliquees ({code_tag('alert_manager.py')})</b> : alarme sonore {code_tag('.wav')} avec duree d'arret auto, notifications Toast barre des taches Windows et emails SMTP asynchrones sans spam (deduplication par hote, incident et severite).", styles))

    # 3.3 SNMP Infrastructure
    story.append(subsection("3.3", "Infrastructure SNMP & Fiche Equipement 10 Onglets (SNMPView — Index 11)", styles))
    story.append(
        p(
            f"Le moteur SNMP ({code_tag('snmp_client.py')}, {code_tag('snmp_engine.py')}, {code_tag('snmp_profiles.py')}) "
            f"decouvre automatiquement les equipements via MIB-II, detecte les redemarrages ({code_tag('sysUpTime')} immunise "
            "contre le debordement 32-bit de 497 jours) et execute un ordonnancement concurrent non chevauchant.",
            styles["Body"],
        )
    )
    snmp_rows = [
        ["Protocoles & Securite", "SNMP v1, v2c et v3 (noAuthNoPriv, authNoPriv, authPriv) : auth MD5/SHA/SHA-256/SHA-512, chiffrement DES/3DES/AES-128/192/256"],
        ["6 Profils Constructeurs", f"{code_tag('cisco_catalyst')}, {code_tag('ruckus')} (ICX/AP), {code_tag('fortinet_fortigate')}, {code_tag('generic_router')}, {code_tag('generic_switch')}, {code_tag('snmp_server')}"],
        ["Sante Materielle", f"{code_tag('device_health.py')} : CPU courant & moyenne historique, RAM via 4 strategies (pools Cisco, HOST-RESOURCES, % direct, total/free), capteurs Temperature avec <b>seuils adaptes au modele et au profil</b>"],
        ["Interfaces 64-bit & Erreurs", f"{code_tag('interface_monitor.py')} : IF-MIB + 64-bit {code_tag('ifXTable')} (repli 32-bit), 6 etats canoniques (UP, DOWN, TESTING, UNKNOWN, DORMANT, NOT_PRESENT), debits Mbps & % utilisation, erreurs CRC/FCS, <b>protection anti-pic</b> sur rollover/reset/reboot"],
        ["PoE & VLANs", f"{code_tag('poe_monitor.py')} (budget total, conso W par port, alerte surcharge) & {code_tag('vlan_monitor.py')} (Q-BRIDGE PortList bitmask + mappings access/trunk Cisco/Ruckus) — jamais de valeurs inventees si non supporte"],
        ["Fiche Details (10 Onglets)", f"{code_tag('device_details_view.py')} : 0 Apercu, 1 CPU & Memoire, 2 Interfaces (6 filtres), 3 Trafic (In/Out & %), 4 PoE*, 5 VLANs*, 6 Syslog, 7 Evenements & Anomalies, 8 Historique (Brut/Horaire/Journalier), 9 Configuration (*masques dynamiquement si non supportes)"],
    ]
    story.append(styled_table(["Capacite SNMP", "Specifications techniques implementees"], snmp_rows, [126, CONTENT_WIDTH - 126], styles, cell_pad=2.6))
    story.append(Spacer(1, 2))

    # 3.4 Syslog Monitor
    story.append(subsection("3.4", "Moniteur Syslog Centralise (SyslogView — Index 12)", styles))
    story.append(bullet(f"<b>Recepteur UDP asynchrone ({code_tag('syslog_server.py')})</b> : ecoute non bloquante en {code_tag('QThread')} sur le port configure (defaut {code_tag('514')} ou {code_tag('5514')}), double limitation anti-flood par jetons (global 2 000 msg/s + par IP 500 msg/s par defaut) et file bornee avec compteur explicite des paquets rejetes.", styles))
    story.append(bullet(f"<b>Parseur robuste RFC 3164 & RFC 5424 ({code_tag('syslog_parser.py')})</b> : decodage des 8 severites RFC (0 Emergency a 7 Debug), extraction {code_tag('STRUCTURED-DATA')} (dont paires cle-valeur FortiGate), variantes Cisco/Ruckus et protection contre paquets binaires, malformes ou surdimensionnes.", styles))
    story.append(bullet(f"<b>Classification multi-constructeurs en 12 categories ({code_tag('syslog_classifier.py')})</b> : {code_tag('POE_OVERLOAD')}, {code_tag('PORT_SECURITY')}, {code_tag('STP_CHANGE')}, {code_tag('REBOOT')}, {code_tag('FIREWALL_IF_DOWN')}, {code_tag('LINK_DOWN')}, {code_tag('LINK_UP')}, {code_tag('AUTH_FAIL')}, {code_tag('CONFIG_CHANGE')}, {code_tag('HIGH_CPU')}, {code_tag('HARDWARE_THERMAL')}, {code_tag('GENERAL')}, plus extraction port/utilisateur, recherche et exports <b>CSV / JSON</b>.", styles))

    # 3.5 Network Intelligence
    story.append(subsection("3.5", "Intelligence Reseau & Correlation Multi-Sources (IntelligenceView — Index 13)", styles))
    story.append(
        p(
            f"L'intelligence reseau associe un detecteur statistique sans dependance lourde ({code_tag('anomaly_detector.py')}) "
            f"a un moteur de correlation deterministe multi-sources ({code_tag('intelligence_engine.py')}). Elle separe toujours "
            "explicitement les <b>Preuves Observees</b> (mesures reelles) de la <b>Cause Probable Inferee</b>.",
            styles["Body"],
        )
    )
    intel_rows = [
        [code_tag("PHYSICAL_LINK_FAILURE"), "Interfaces SNMP + Syslog + Ping", "Port DOWN ou erreurs/discards correle avec evenement LINK_DOWN / FIREWALL_IF_DOWN"],
        [code_tag("SWITCH_OVERLOAD"), "SNMP Sante + Interfaces + Syslog", "Saturation CPU/RAM ou temperature critique correlee avec congestion ou alerte thermique"],
        [code_tag("POE_BUDGET_EXHAUSTION"), "SNMP PoE + Syslog + Interfaces", "Consommation PoE proche ou au-dela du budget / alerte POE_OVERLOAD"],
        [code_tag("UNEXPECTED_REBOOT"), "SNMP sysUpTime + Syslog + Ping", "Chute anormale de l'uptime ou message Syslog REBOOT avec coupure associee"],
        [code_tag("INTERFACE_ERROR_DEGRADATION"), "SNMP IF-MIB / EtherLike + Historique", "Hausse persistante des erreurs d'entree/sortie, CRC/FCS ou paquets ecartes"],
        [code_tag("SYSLOG_SECURITY_BURST"), "Syslog Securite + Ping/SNMP", "Rafale d'echecs d'authentification (AUTH_FAIL) ou violations PORT_SECURITY"],
    ]
    story.append(styled_table(["Regle de Correlation", "Sources croisees", "Diagnostic & comportement"], intel_rows, [158, 116, CONTENT_WIDTH - 274], styles, cell_pad=2.4))
    story.append(Spacer(1, 2))
    story.append(bullet(f"<b>Detection statistique legere ({code_tag('StatisticalAnomalyDetector')})</b> : baseline glissante + z-score avec garde-fou anti-fausse-alerte sur metriques stables (<i>flatline floor</i>), confirmation sur N echantillons consecutifs, fenetre de cooldown par equipement/metrique, bouton d'activation/desactivation par equipement et resolution automatique des que la situation revient a la normale.", styles))

    # 3.6 Global Status
    story.append(subsection("3.6", "Etat des Services Globaux (ServiceStatusView — Index 9)", styles))
    story.append(
        p(
            f"Accessible via {code_tag('src/ui/widgets/service_status_view.py')}, cet ecran propose des cartes interactives "
            "avec logos vectoriels pour ouvrir directement en 1 clic les portails de statut officiels d'<b>Apple</b> "
            "(iCloud, App Store), <b>Netflix</b> et <b>PlayStation Network</b> dans le navigateur systeme.",
            styles["Body"],
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_4(styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "04",
            "Outils de Diagnostic & Performance (3 Modules)",
            p(
                "Le groupe <b>Outils</b> fournit des utilitaires terrain haute performance remplaçant les commandes "
                "eparses (Angry IP Scanner, tracert, nslookup, audits Wi-Fi, speedtest).",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("4.1", "Scanners Reseau — 5 Modes Integres (ScannerView — Index 3)", styles))
    scan_rows = [
        ["1. Scan LAN Intelligent", "Sous-reseaux /24 : requetes ARP broadcast via Scapy (si Npcap present) ou scan ICMP multithread (30 workers). Grands reseaux (/16+) : lecture rapide table ARP + DNS inverse asynchrone."],
        ["2. Scan de Ports TCP", "Moteur asyncio jusqu'a 200 connexions simultanees : mode rapide (ports courants standards) ou plage personnalisee 1-65535."],
        ["3. Traceroute Temps Reel", "Execution en direct (tracert -d -w 2000) avec affichage saut par saut (Hop #, IP, RTT1/RTT2/RTT3, Etat) compatible Windows FR et EN."],
        ["4. Scanner Wi-Fi BSSID", "Analyse via netsh wlan show networks mode=bssid (decodage UTF-8 / CP850) listant chaque BSSID physique meme sous un SSID commun (ideal audits bornes Ruckus/UniFi), signal %, canal, bande 2.4/5/6 GHz et norme."],
        ["5. Smart Diagnostic (5 Etapes)", "Diagnostic sequentiel automatise : Carte reseau locale -> Passerelle par defaut -> Connectivite WAN (8.8.8.8 / 1.1.1.1) -> Resolution DNS -> Verdict global identifiant le maillon en panne."],
    ]
    story.append(styled_table(["Mode de Scan", "Fonctionnement et cas d'usage"], scan_rows, [130, CONTENT_WIDTH - 130], styles))
    story.append(Spacer(1, 8))

    story.append(subsection("4.2", "Boite a Outils IT Multi-Onglets (ToolsView — Index 2)", styles))
    story.append(
        p(
            f"Implementee dans {code_tag('src/ui/widgets/tools_view.py')} et {code_tag('src/core/tools.py')}, la boite a outils "
            "execute plusieurs diagnostics en parallele dans des terminaux a onglets avec horodatage et coloration syntaxique "
            f"(reponses en vert, timeouts/erreurs en rouge, IP en cyan, latences en ambre) et export en fichier {code_tag('.txt')} :",
            styles["Body"],
        )
    )
    story.append(bullet("<b>7 Outils disponibles</b> : <i>Ping</i> (ponctuel ou mode infini), <i>Traceroute</i>, <i>NSLookup</i>, <i>Netstat</i> (connexions actives), <i>Whois (RDAP)</i>, <i>Port Checker</i> (cible + port specifique) et <i>Load Balancing</i> (detection de plusieurs IPs publiques sortantes).", styles))

    story.append(subsection("4.3", "Test de Performance & Rapport PDF (SpeedtestView — Index 6)", styles))
    story.append(
        p(
            f"Le module {code_tag('src/core/speedtest.py')} / {code_tag('speedtest_view.py')} mesure le debit descendant "
            "(Download Mbps), le debit montant (Upload Mbps), la latence (Ping ms), la gigue (Jitter ms) et la perte de "
            "paquets (%) avec selection automatique ou manuelle de serveurs de test, sauvegarde automatique des derniers "
            f"resultats dans {code_tag('speed_tests')} et export PDF via {code_tag('PDFReportGenerator.generate_speedtest_report()')} "
            "incluant graphique d'evolution sur 10 tests, IP publique et matrice d'eligibilite (Navigation Web, Visioconference, "
            "Streaming 4K, Jeu en ligne).",
            styles["Body"],
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_5(styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "05",
            "Administration, Multi-Sites & Infrastructure Management (8 Modules)",
            p(
                "Les groupes <b>Gestion</b> et <b>Infrastructure</b> constituent le coeur de Roadmap 03 (v3.6.0) : "
                "decouverte topologique, inventaire cycle de vie, gouvernance VLAN, sauvegardes chiffrees DPAPI, "
                "acces SSH durci et audit immuable multi-sites.",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("5.1", "Gestionnaire Web Integre (BrowserView — Index 7)", styles))
    story.append(bullet(f"<b>Navigateur Chromium embarque ({code_tag('browser_view.py')})</b> : base sur {code_tag('QWebEngineView')} avec barre d'adresse, navigation, barre de progression et mode <b>Plein Ecran</b>.", styles))
    story.append(bullet(f"<b>Tolerance TLS pour equipements LAN/RFC1918</b> : accepte les certificats auto-signes sur les plages privees ({code_tag('192.168.*')}, {code_tag('10.*')}, {code_tag('172.16.*')}, {code_tag('localhost')}).", styles))

    story.append(subsection("5.2", "Centre d'Acces Reseau & Administration (RemoteView — Index 8)", styles))
    story.append(bullet(f"<b>Multi-sessions & Profils SSH DPAPI ({code_tag('remote_view.py')}, {code_tag('ssh_access.py')})</b> : onglets de sessions paralleles SSH, Telnet et Serie COM, profils d'identifiants chiffres DPAPI.", styles))
    story.append(bullet("<b>Verification stricte known_hosts</b> : utilisation exclusive de StrictVerifyHostKeyPolicy (aucun AutoAddPolicy) avec confirmation TOFU explicite et rejet des empreintes alterees.", styles))
    story.append(bullet("<b>Garde CLI par niveaux</b> : classification READ_ONLY (direct), MODIFYING et DESTRUCTIVE (confirmation + ticket obligatoires), boutons diagnostics par constructeur, export de log masque et lanceurs HTTPS / RDP (mstsc) / SNMP.", styles))

    story.append(subsection("5.3", "Gestion d'Infrastructure Multi-Sites (SitesView — Index 10)", styles))
    story.append(bullet(f"<b>Hierarchie & Connectivite ({code_tag('site_manager.py')})</b> : arborescence Organisation -> Region -> Site, sous-reseaux CIDR, passerelle, DNS, FAI et modes LOCAL / VPN / REMOTE_AUTHORIZED.", styles))
    story.append(bullet("<b>Dashboard & Comparaison</b> : KPI de disponibilite, latence moyenne, incidents ouverts, Ping Batch non bloquant, ouverture directe en Topologie/Acces et exports CSV / PDF Corporate.", styles))

    story.append(subsection("5.4", "Topologie Reseau Automatique (TopologyView — Index 14)", styles))
    story.append(bullet(f"<b>Decouverte en direct du reseau actuel ({code_tag('discover_live_local_network')})</b> : un clic sur <i>Decouvrir Topologie</i> analyse uniquement les equipements presents a l'instant meme (balayage sous-reseau actif, table ARP locale, passerelle par defaut, station locale et SNMP joignables LLDP/CDP/FDB/Routage) sans melanger les anciens sites ni polluer la base SQLite. Un bandeau dedie et le bouton <b>+ Ajouter au Site...</b> (carte ou lot complet via {code_tag('AssignToSiteDialog')}) permettent d'enregistrer un ou plusieurs equipements vers un site existant ou cree a la volee.", styles))
    story.append(bullet(f"<b>Moteur multi-sources &amp; Hierarchie directionnelle ({code_tag('topology_discovery.py')})</b> : correlation LLDP (IEEE 802.1AB), CDP, BRIDGE/Q-BRIDGE FDB (inference switch non manage si >= 2 MACs sur port non-LLDP), routage IP, ARP local, identification constructeur OUI seul (jamais de devinette de type depuis la MAC) et orientation automatique des liens <b>Uplink -> Downstream</b> (Passerelle Internet/WAN -> Switches -> Bornes/Terminaux).", styles))
    story.append(bullet(f"<b>Cartes Pro Omada/UniFi &amp; Fleches directionnelles ({code_tag('topology_graph.py')})</b> : grille de points, cartes materielles avec icones vectorielles dediees, pastille latence/etat, badge PASSERELLE/CE PC/NOUVEAU, courbes de Bezier flechees avec info-bulles et inspecteur detaillant <i>Alimente par (Uplink)</i> et <i>Alimente (Downstream)</i>, 4 modes (PHYSICAL, LOGICAL, VLAN, SITE), disposition auto hierarchique 200+ noeuds et export PNG.", styles))

    story.append(subsection("5.5", "Inventaire Avance des Equipements (InventoryView — Index 15)", styles))
    story.append(bullet(f"<b>Parc sur 11 categories ({code_tag('inventory_manager.py')})</b> : pare-feux, routeurs, switches Core/Distribution/Access, controleurs Wi-Fi, bornes, serveurs, onduleurs, imprimantes et autres equipements avec champs personnalises, tags et baies.", styles))
    story.append(bullet("<b>Cycle de vie & Qualite des donnees</b> : dates d'achat et expiration de garantie avec rappels, detection de doublons IP/MAC, synchronisation non destructive depuis SNMP/Hotes/Sites, import CSV et rapports PDF.", styles))

    story.append(subsection("5.6", "Gestion des VLANs Multi-Switchs (VLANView — Index 16)", styles))
    story.append(bullet(f"<b>Visibilite & Coherence ({code_tag('vlan_manager.py')})</b> : synchronisation SNMP + parseurs CLI Cisco IOS, Ruckus ICX et Fortinet FortiGate ; matrice multi-switchs et alertes NAME_MISMATCH, TRUNK_VLAN_GAP et INACTIVE_WITH_PORTS.", styles))
    story.append(bullet("<b>Planificateur CLI controle</b> : generation de commandes adaptees au constructeur (sans jamais supposer la compatibilite Cisco), blocage des suppressions VLAN 1 / injections et execution uniquement apres confirmation explicite + journalisation audit.", styles))

    story.append(subsection("5.7", "Sauvegardes Chiffrees, Diff Visuel & Restauration Controlee (BackupView — Index 17)", styles))
    story.append(bullet(f"<b>Adaptateurs & Stockage securise ({code_tag('backup_manager.py')}, {code_tag('backup_adapters.py')})</b> : adaptateurs Cisco IOS, Ruckus ICX, Ruckus SmartZone API, FortiGate et Generic SSH ; chiffrement Windows DPAPI (BHITENC1:) + SHA-256 (|CHK:) avec isolation des echecs par lot.", styles))
    story.append(bullet(f"<b>Diff Visuel, Modeles & Restore ({code_tag('config_diff.py')}, {code_tag('config_templates.py')})</b> : comparaison cote a cote / unifiee avec masquage automatique des secrets (exports HTML/TXT), 8 modeles parametres et restauration avec verification d'integrite/compatibilite + sauvegarde PRE_RESTORE obligatoire.", styles))

    story.append(subsection("5.8", "Journal d'Audit Immuable (AuditView — Index 18)", styles))
    story.append(bullet(f"<b>Tracabilite append-only ({code_tag('audit_logger.py')}, {code_tag('audit_view.py')})</b> : enregistrement horodate de chaque operation, blocage, modification IP/VLAN, template, sauvegarde et restauration avec verification d'empreinte SHA-256 et protection SQLite contre UPDATE/DELETE.", styles))
    story.append(Spacer(1, 8))
    return story


def build_chapter_6(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "06",
            "Configuration Systeme & Parametres Globaux (2 Modules)",
            p(
                "Le groupe <b>Systeme</b> centralise la configuration IPv4 du poste d'administration et le "
                "reglage transversal du comportement de l'application, des alertes, des pilotes et des sauvegardes.",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("6.1", "Configuration Reseau IPv4 (ConfigView — Index 4)", styles))
    story.append(
        p(
            f"Implementee dans {code_tag('src/ui/widgets/config_view.py')} et {code_tag('src/core/net_config.py')}, cette vue "
            f"detecte prioritairement la carte reseau active via {code_tag('psutil')} et lit la configuration actuelle "
            "(Adresse IPv4, Masque de sous-reseau, Passerelle par defaut, DNS Primaire et Secondaire) avec support complet des "
            "sorties Windows francaises et anglaises. Elle permet en 1 clic d'appliquer une configuration <b>IP Statique + DNS</b> "
            "ou de rebasculer la carte en <b>DHCP</b> (elevation Administrateur controlee par banniere UAC).",
            styles["Body"],
        )
    )

    story.append(subsection("6.2", "Parametres Globaux — 4 Onglets (SettingsView — Index 5)", styles))
    set_rows = [
        ["1. General", f"Mode Fantome (reduction barre des taches au lieu de quitter), Option securite SSL/TLS WebEngine, Lancement silencieux au demarrage Windows ({code_tag('HKCU\\...\\Run --silent')}), Selecteur de langue Francais / Anglais ({meta['fr_keys']} cles 1:1 — redemarrage conseille pour application complete), Verificateur de mise a jour OTA."],
        ["2. Alertes (Son & Email)", "Activation et choix d'un fichier alarme .wav personnalise + bouton Test Son ; configuration SMTP personnalisee (hote, port, utilisateur, mot de passe app chiffre DPAPI, expediteur), declenchement apres N echecs DOWN, alerte de retablissement UP et envoi d'email de test."],
        ["3. Moteur Reseau", "Controle en direct de la presence du pilote Npcap sur le poste Windows avec lien de telechargement officiel et bouton de re-verification."],
        ["4. Sauvegarde, Sync & Stockage", "Acces rapide aux dossiers locaux Base de Donnees et Journaux ; Export/Import de sauvegarde JSON (hotes, sites, preferences) ; Synchronisation Cloud via compte Supabase (connexion, sauvegarde, restauration, deconnexion)."],
    ]
    story.append(styled_table(["Onglet Parametres", "Options et actions disponibles"], set_rows, [125, CONTENT_WIDTH - 125], styles))
    story.append(Spacer(1, 8))

    story.append(subsection("6.3", "Emplacements Locaux, Raccourcis & Reprise d'Exploitation", styles))
    loc_rows = [
        [code_tag("config.json"), "Preferences generales, parametres ping/SNMP/Syslog et mot de passe SMTP chiffre DPAPI."],
        [code_tag("network_tools.db"), f"Base SQLite WAL locale contenant l'ensemble des {meta['table_count']} tables de supervision et d'infrastructure."],
        [code_tag("session.dat"), "Jeton d'authentification Supabase Cloud chiffre via CryptProtectData (Windows DPAPI)."],
        [code_tag("BahaaIT Logs"), "Journaux applicatifs rotatifs accessibles en 1 clic via Parametres > Sauvegarde, Sync & Stockage."],
    ]
    story.append(styled_table(["Ressource locale", "Role & comportement en sauvegarde/restauration"], loc_rows, [130, CONTENT_WIDTH - 130], styles))
    story.append(Spacer(1, 8))
    story.append(
        callout_box(
            "Portabilite des sauvegardes JSON et chiffrement DPAPI",
            "Lors d'une sauvegarde vers un autre poste Windows ou apres reinstallation systeme, les mots de passe SMTP "
            "et secrets SNMP chiffres via DPAPI sont lies au profil utilisateur et a la machine d'origine. Il convient de "
            "resaisir ces identifiants sur le nouveau poste si l'import JSON est restaure sur une autre machine.",
            styles,
            tone="warn",
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_7(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "07",
            f"Base de Donnees SQLite & Politique de Retention ({meta['table_count']} Tables)",
            p(
                f"La persistance locale repose sur <b>SQLAlchemy 2.0</b> et <b>SQLite</b> ({code_tag('src/utils/db.py')}) "
                f"configures en mode journalise <b>WAL</b> ({code_tag('Write-Ahead Logging')}), "
                f"{code_tag('PRAGMA foreign_keys=ON')} et {code_tag('busy_timeout=5000')} ms pour absorber les ecritures "
                "concurrentes des moteurs Ping, SNMP et Syslog sans verrouiller l'interface. Lors de toute montee de version, "
                "une migration automatique non destructive ajoute les nouvelles tables et colonnes en preservant l'historique existant.",
                styles["Body"],
            ),
        )
    )

    db_rows = [
        ["Ping & Supervision", code_tag("hosts"), "Liste des hotes ICMP, seuils, etat courant, SLA", "Persistant (cascade sur logs/mesures)"],
        ["Ping & Supervision", code_tag("monitoring_logs"), "Journal des transitions d'etat et evenements ping", "30 j par defaut (cleanup_old_logs)"],
        ["Ping & Supervision", code_tag("ping_measurements"), "Mesures ICMP brutes (latence, code issue probe)", "7 j (retention_raw_days)"],
        ["Ping & Supervision", code_tag("monitoring_incidents"), "Incidents DETECTED->CLOSED et commentaires", "365 j (retention_incidents_days)"],
        ["Ping & Supervision", code_tag("alert_events"), "Historique des alertes son/toast/SMTP & dedup", "365 j (retention_alerts_days)"],
        ["Ping & Supervision", code_tag("monitoring_policies"), "Politiques globales ou specifiques par hote", "Persistant"],
        ["Ping & Supervision", code_tag("monitoring_statistics"), "Aggregats periodiques (avg, min, max, p95, perte)", "90 j (retention_aggregated_days)"],
        ["SNMP & Sante", code_tag("snmp_devices"), "Inventaire SNMP, profil, capacites, creds DPAPI", "Persistant"],
        ["SNMP & Sante", code_tag("snmp_metrics"), "Metriques brutes CPU, RAM, Temperature, PoE, Uptime", "7 j (retention_snmp_raw_days)"],
        ["SNMP & Sante", code_tag("snmp_metrics_aggregated"), "Aggregats horaires/journaliers (min, avg, max)", "90 j (retention_snmp_aggregated_days)"],
        ["SNMP & Sante", code_tag("snmp_interfaces"), "Metadonnees interfaces (ifIndex, nom, alias, MAC, speed)", "Persistant par equipement"],
        ["SNMP & Sante", code_tag("interface_measurements"), "Compteurs 64-bit Mbps, util %, erreurs, discards, CRC", "7 j (retention_snmp_raw_days)"],
        ["SNMP & Sante", code_tag("snmp_vlans"), "VLANs decouverts, noms, ports access/tagged/trunk", "Persistant par equipement"],
        ["Syslog & IA", code_tag("syslog_events"), "Messages RFC 3164/5424 normalises & 12 categories", "30 j (retention_syslog_days)"],
        ["Syslog & IA", code_tag("network_anomalies"), "Anomalies statistiques + correlations multi-sources", "365 j (retention_anomalies_days)"],
        ["Tests & Services", code_tag("speed_tests"), "Historique tests Speedtest (DL, UL, Ping, Jitter, Loss)", "100 derniers tests"],
        ["Tests & Services", code_tag("global_services"), "Catalogue services cloud personnalises/suivis", "Persistant"],
        ["Tests & Services", code_tag("global_service_logs"), "Historique disponibilite et latence des services", "Purge associee"],
        ["Infrastructure (v3.6)", code_tag("network_sites"), "Sites hierarchiques Org->Region->Site, CIDR, DNS, FAI", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("ssh_profiles"), "Profils SSH/cle privee avec secrets DPAPI & politique host-key", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("infrastructure_devices"), "Inventaire unifie 11 categories, garantie, tags, rack", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("device_interfaces"), "Interfaces, mode access/trunk, VLAN natif & tagges", "Cascade equipement"],
        ["Infrastructure (v3.6)", code_tag("network_links"), "Liens topologiques LLDP/CDP/FDB/Routage + niveau confiance", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("topology_layouts"), "Positions manuelles sauvegardees & zoom par vue/site", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("infrastructure_vlans"), "VLANs multi-equipements & attribution access/tagged/trunk", "Cascade equipement"],
        ["Infrastructure (v3.6)", code_tag("configuration_backups"), "Metadonnees sauvegardes DPAPI, SHA-256 & PRE_RESTORE", "Retention 90j / >=3 copies"],
        ["Infrastructure (v3.6)", code_tag("configuration_changes"), "Historique diffs rediges & sections modifiees", "Persistant"],
        ["Infrastructure (v3.6)", code_tag("infrastructure_audit"), "Journal immuable append-only + SHA-256 (triggers no UPDATE/DELETE)", "Immuable (Triggers SQLite)"],
    ]
    story.append(
        styled_table(
            ["Domaine", "Table SQLite", "Role principal", "Retention par defaut"],
            db_rows,
            [78, 128, 156, CONTENT_WIDTH - 362],
            styles,
            cell_pad=2.7,
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        callout_box(
            "Immuabilite Audit & Sauvegarde SQLite (v3.6.0)",
            f"Les triggers SQLite {code_tag('trg_infra_audit_no_update')} et {code_tag('trg_infra_audit_no_delete')} "
            f"empechent toute modification ou suppression dans {code_tag('infrastructure_audit')}. La methode "
            f"{code_tag('DatabaseManager.backup_database()')} permet une copie coherente a chaud via l'API SQLite backup.",
            styles,
            tone="tip",
        )
    )
    story.append(PageBreak())
    return story


def build_chapter_8(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "08",
            "Qualite Logicielle, Benchmarks Mesures & Packaging",
            p(
                f"La fiabilite de BahaaIT Network Tools repose sur une couverture automatisee {code_tag('pytest')} "
                "executee avant chaque livraison et sur des essais de charge reproduisant des environnements de "
                "production (100+ hotes Ping, 100 equipements SNMP et rafales Syslog UDP).",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("8.1", "Cartographie de la Suite de Tests Automatises (tests/)", styles))
    test_rows = [
        [code_tag("test_core.py"), "CRUD SQLite, Uptime/SLA, ConfigManager, DPAPI, scanners ARP/Ports/Tracert FR-EN, Wi-Fi BSSID, Smart Diag"],
        [code_tag("test_intelligent_monitoring.py"), "Machine a 4 etats hysteresis, AsyncPingEngine 100+ hotes, incidents, alertes dedup, verdicts WAN, retention SQLite"],
        [code_tag("test_monitoring_ui.py"), "Integrite UI MonitorView, IncidentCenter (commentaires/PDF), HostDetailsDialog, synchronisation widgets, version"],
        [code_tag("test_snmp_foundation.py"), "Connectivite SNMP v1/v2c/v3, vault DPAPI + secret scrubbing, migration DB non destructive, decouverte & reboot 497j"],
        [code_tag("test_snmp_metrics_interfaces.py"), "Sante CPU/RAM/Temperature par modele, interfaces 64-bit, protection rollover/reset/reboot, PoE & VLAN PortList"],
        [code_tag("test_syslog_engine.py"), "Parseur RFC 3164/5424, protection binaire/oversized, ecoute UDP, anti-flood dual token-bucket, exports CSV/JSON"],
        [code_tag("test_network_intelligence.py"), "Correlations physiques/overload/PoE/reboot/erreurs/securite, z-score/flatline, benchmark 100 SNMP + 1 000 Syslog"],
        [code_tag("test_network_intelligence_ui.py"), f"Dashboard 10 KPI/8 graphiques, SNMPView, Fiche 10 onglets dynamiques, SyslogView, IntelligenceView, {meta['fr_keys']}/{meta['en_keys']} i18n, build"],
        [code_tag("test_v360_inventory_sites.py"), "Inventaire 11 cat., doublons IP/MAC, CSV/PDF, multi-sites & comparaison, DPAPI, SHA-256, triggers immuabilite audit"],
        [code_tag("test_v360_topology.py"), "ARP, classification sans OUI->type, LLDP/CDP/FDB/Routage, decouverte live isolee, hierarchie directionnelle, ajout site & 210 noeuds"],
        [code_tag("test_v360_vlan_backup_templates.py"), "VLAN SNMP/CLI Cisco/Ruckus/FortiGate, incoherences, backups DPAPI+tamper SHA-256, Diff visuel, Restore & Modeles"],
        [code_tag("test_v360_access_audit_security.py"), "Tiers CLI READ_ONLY/MODIFYING/DESTRUCTIVE, blocage non confirme, known_hosts strict (zero AutoAddPolicy), UI Access/Sites/Audit"],
        [code_tag("test_v360_ui_benchmarks.py"), "Benchmarks echelle (1 000 equipements, 250 noeuds, 25 sites, 50 backups DPAPI), parite 1:1 FR/EN & wiring 19 ecrans"],
        [code_tag("test_updater_dialog.py"), "Rendu Markdown->HTML et fenetre OTA UpdateAvailableDialog a dimensions bornees et defilement vertical"],
        [code_tag("test_ui_design_audit.py"), "Audit UI/UX automatise (Quantum Midnight v2) : QSS strict, icones SVG, absence secret en clair, parite i18n, zero debordement/troncature sur 18 vues"],
        [code_tag("test_documentation_pdf.py"), "Verification automatique de generation PDF, validite structurelle, pagination, contenu v3.6.0 et version active"],
    ]
    story.append(styled_table(["Fichier de test", "Perimetre verifie"], test_rows, [165, CONTENT_WIDTH - 165], styles))
    story.append(Spacer(1, 8))

    story.append(subsection("8.2", "Benchmarks Mesures (v3.5.0 & Echelle Infrastructure v3.6.0)", styles))
    bench_rows = [
        ["Cycle de collecte SNMP (2 x 100 equipements)", "1,022 s", "50 slots concurrents, sante + interfaces 64-bit + VLAN/PoE + flush SQLite par lots (note : 2,409 s sous charge complete pytest)"],
        ["Ingestion UDP Syslog (1 000 datagrammes loopback)", "0,261 s (3 825 msg/s)", "0 paquet perdu, classification multi-constructeurs et persistance SQLite complete"],
        ["Correlation multi-sources sur 100 equipements", "0,471 s", "Detection exacte de 5 pannes croisees injectees (SNMP + Interfaces + PoE + Syslog)"],
        ["Inventaire Infrastructure : insertion 1 000 equipements", "0,789 s", "Ecriture SQLite batch + requete/filtre/doublons/export CSV en 0,308 s"],
        ["Topologie : calcul disposition 250 noeuds (4 modes)", "0,007 s", "Layout deterministe PHYSICAL, LOGICAL, VLAN et SITE sur graphe 250 noeuds"],
        ["Multi-Sites : comparaison 25 sites & Sauvegarde 50 equip.", "0,505 s / 8,120 s", "Comparaison agregation 25 sites en 0,505 s ; 50 sauvegardes chiffrees DPAPI+SHA-256 + auto-diff en 8,120 s"],
    ]
    story.append(styled_table(["Scenario de charge mesure", "Resultat observe", "Conditions & couverture"], bench_rows, [195, 105, CONTENT_WIDTH - 300], styles, center_cols=[1]))
    story.append(Spacer(1, 8))

    story.append(subsection("8.3", "Chaine de Compilation & Packaging Windows", styles))
    installer_name = f"Install_BahaaIT_{meta['version']}.exe"
    story.append(bullet(f"<b>Compilation PyInstaller ({code_tag('build_scripts/build.py')} &amp; {code_tag('BahaaIT.spec')})</b> : genere le dossier autonome {code_tag('dist/BahaaIT')} ({code_tag('--onedir')}, {code_tag('--noconfirm')}) en incluant explicitement {code_tag('pysnmp')}, {code_tag('pysnmpcrypto')}, {code_tag('pyasn1')}, {code_tag('pyqtgraph')}, {code_tag('paramiko')}, {code_tag('icmplib')}, {code_tag('serial.tools.list_ports')}, {code_tag('reportlab.graphics.shapes')}, les 5 vues v3.6.0 ({code_tag('topology_view')}..{code_tag('audit_view')}), {code_tag('assets/')} et {code_tag('src/assets/')}.", styles))
    story.append(bullet(f"<b>Installateur Inno Setup ({code_tag('build_scripts/setup_compiler.iss')})</b> : synchronise automatiquement la version depuis {code_tag('updater.py')} et produit {code_tag(installer_name)} avec creation de raccourcis et lancement post-installation.", styles))
    story.append(PageBreak())
    return story


def build_chapter_9(meta: Dict[str, object], styles: Dict[str, ParagraphStyle]) -> List[Flowable]:
    story: List[Flowable] = []
    story.append(
        section_banner(
            "09",
            "Politique de Maintenance Continue & Journal des Versions",
            p(
                "Ce document est concu comme une <b>documentation vivante</b> integree au code source. "
                "Toute nouvelle fonctionnalite, correction majeure ou evolution d'architecture doit se refleter "
                "immediatement dans le script generateur et le PDF compile.",
                styles["Body"],
            ),
        )
    )

    story.append(subsection("9.1", "Protocole Obligatoire lors de Toute Evolution Applicative", styles))
    story.append(
        callout_box(
            "Checklist de mise a jour documentaire (Regle projet AGENTS.md)",
            f"1. Mettre a jour la section concernee dans {code_tag('docs/generate_documentation_pdf.py')} (nouveau module, nouveau param, nouvelle table DB, nouvelle regle, etc.).<br/>"
            f"2. Ajouter une entree datee/versionnee dans le <b>Journal des Versions (Section 9.2)</b> ci-dessous.<br/>"
            f"3. Executer {code_tag('python docs/generate_documentation_pdf.py')} pour regenerer {code_tag('docs/Documentation_BahaaIT_Network_Tools.pdf')}.<br/>"
            f"4. Verifier via {code_tag('pytest tests/test_documentation_pdf.py -v --timeout=30')} que le PDF compile sans erreur et affiche la version courante.",
            styles,
            tone="tip",
        )
    )
    story.append(Spacer(1, 10))

    story.append(subsection("9.2", "Journal des Versions (Changelog Officiel)", styles))
    changelog_rows = [
        [
            "<b>v3.6.1</b>",
            "Actuelle",
            "<b>Topologie Reseau Live Pro (Omada/UniFi) &amp; Refonte UI Quantum Midnight v2 :</b><br/>"
            "• <b>Topologie Live isolee</b> : decouverte du reseau actuel uniquement (balayage actif + ARP filtre + passerelle + SNMP joignables) via bandeau Live dedie, sans melanger les anciens sites ni ecrire sans confirmation.<br/>"
            "• <b>Ajout au Site en 1 clic</b> : bouton + Ajouter au Site... par carte, clic droit et lot complet (+ Tout Ajouter au Site...) avec creation de site a la volee (passerelle &amp; CIDR auto-detectes).<br/>"
            "• <b>Cartes Omada/UniFi &amp; Hierarchie directionnelle</b> : cartes vectorielles avec couronne INTERNET/WAN, pastille latence, courbes de Bezier flechees Uplink -> Downstream et inspecteur <i>Alimente par / Alimente</i>.<br/>"
            f"• <b>Audit UI/UX complet 19 ecrans ({code_tag('test_ui_design_audit.py')})</b> : icones SVG dediees ({code_tag('assets/icons/')}), cadres isoles ({code_tag('#PanelCard/#FilterBar/#KpiCard')}), barres 2 lignes sans troncature, fenetre redimensionnable, suppression secret SMTP en clair et correctifs QThread.",
        ],
        [
            "<b>v3.6.0</b>",
            "Precedente",
            "<b>Roadmap 03 — Infrastructure Management Platform :</b><br/>"
            "• <b>Topologie Reseau</b> : decouverte multi-sources (LLDP, CDP, Bridge MIB FDB, Routage, ARP), sondes ICMP/TCP live &amp; Verifier Statuts, OUI constructeur seul, carte QGraphicsView 4 modes.<br/>"
            "• <b>Inventaire Avance (11 categories)</b> : synchro SNMP/Hotes/Sites, cycle de vie &amp; garanties, doublons IP/MAC, CSV &amp; PDF Corporate.<br/>"
            "• <b>Gestion des VLANs</b> : parseurs Cisco/Ruckus/FortiGate, matrice multi-switchs, incoherences et planificateur CLI confirme.<br/>"
            "• <b>Sauvegardes DPAPI+SHA-256, Diff Visuel, 8 Modeles &amp; Restauration</b> : stockage chiffre BHITENC1:+CHK, masquage secrets et PRE_RESTORE obligatoire.<br/>"
            "• <b>Centre d'Acces (known_hosts strict), Multi-Sites &amp; Audit Immuable</b> : triggers anti-UPDATE/DELETE, 19 modules, 28 tables SQLite et fenetre OTA scrollable <b>UpdateAvailableDialog</b>.",
        ],
        [
            "<b>v3.5.0</b>",
            "Precedente",
            "<b>Roadmap 02 — Network Intelligence Platform :</b><br/>"
            "• Moteur <b>SNMP v1/v2c/v3</b> complet avec chiffrement Windows DPAPI et 6 profils constructeurs (Cisco Catalyst, Ruckus, Fortinet FortiGate, Routeur/Switch/Serveur generiques).<br/>"
            "• Collecte Sante (CPU, RAM 4 strategies, Temperature par modele), Interfaces 64-bit ifXTable (anti-spike rollover/reset/reboot, CRC/FCS), PoE et VLANs Q-BRIDGE/Cisco/Ruckus.<br/>"
            "• <b>Moniteur Syslog UDP</b> asynchrone RFC 3164/5424, anti-flood double token-bucket, 12 categories et exports CSV/JSON.<br/>"
            "• <b>Intelligence Reseau</b> : detecteur statistique z-score/flatline + correlation multi-sources (6 regles, Preuves Observees vs Cause Probable Inferee).",
        ],
        [
            "<b>v3.4.0</b>",
            "Precedente",
            "<b>Roadmap 01 — Intelligent Ping Monitoring :</b><br/>"
            "• Moteur <b>AsyncPingEngine</b> (100+ hotes, 4 issues de sonde, SQLite WAL non destructif).<br/>"
            "• Machine a 4 etats avec hysteresis (UP, DEGRADED, DOWN, RECOVERING, PAUSED) et statistiques 1m/5m/15m/1h/24h (IPDV Jitter, P95, Perte %, SLA).<br/>"
            "• <b>Centre d'Incidents</b> complet (acquittement, commentaires horodates, suppression, CSV et PDF Corporate).<br/>"
            "• Onglet <b>Intelligence WAN</b> (9 verdicts diagnostiques Passerelle / 8.8.8.8 / 1.1.1.1 / DNS / HTTPS) et alertes Audio/Toast/SMTP dedupliquees.",
        ],
        [
            "<b>v3.3.0</b>",
            "Historique",
            "<b>Socle Modulaire Multi-Outils (11 Modules) :</b><br/>"
            "• Dashboard temps reel, Supervision ICMP initiale, Etat des Services, Scanners 5 modes (dont Wi-Fi BSSID & Smart Diagnostic), Boite a Outils 7 terminaux, Speedtest + rapport PDF, Web Manager Chromium (TLS LAN), Terminal Distant SSH/Telnet/Serie, Gestionnaire de Sites, Config IPv4/DHCP, Parametres/Sync Cloud Supabase/OTA GitHub.",
        ],
    ]
    story.append(styled_table(["Version", "Statut", "Evolutions majeures & fonctionnalites livrees"], changelog_rows, [62, 62, CONTENT_WIDTH - 124], styles, center_cols=[0, 1]))
    story.append(Spacer(1, 10))
    story.append(
        p(
            f"<i>Fin du document — BahaaIT Network Tools {esc(str(meta['version']))} — Genere le {esc(str(meta['generated_date']))}.</i>",
            ParagraphStyle("DocEnd", parent=styles["BodyLeft"], textColor=C_MUTED, alignment=TA_CENTER),
        )
    )
    return story


def generate_documentation_pdf(output_path: Optional[Union[str, Path]] = None) -> Path:
    """Genere la documentation PDF complete et retourne le chemin du fichier produit."""
    meta = load_repo_metadata()
    out = Path(output_path) if output_path else DEFAULT_OUTPUT_PDF
    out.parent.mkdir(parents=True, exist_ok=True)

    styles = build_styles()
    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        title=f"BahaaIT Network Tools {meta['version']} — Documentation Officielle",
        author="BahaaIT",
        subject="Documentation Technique et Guide Utilisateur BahaaIT Network Tools",
        creator="docs/generate_documentation_pdf.py (ReportLab)",
        leftMargin=MARGIN_LEFT,
        rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
    )

    story: List[Flowable] = []
    story.extend(build_cover_page(meta, styles))
    story.extend(build_toc_and_overview(meta, styles))
    story.extend(build_chapter_1(meta, styles))
    story.extend(build_chapter_2(meta, styles))
    story.extend(build_chapter_3(styles))
    story.extend(build_chapter_4(styles))
    story.extend(build_chapter_5(styles))
    story.extend(build_chapter_6(meta, styles))
    story.extend(build_chapter_7(meta, styles))
    story.extend(build_chapter_8(meta, styles))
    story.extend(build_chapter_9(meta, styles))

    def _canvas_maker(*args, **kwargs):
        return NumberedCanvas(
            *args,
            doc_version=str(meta["version"]),
            doc_date=str(meta["generated_date"]),
            **kwargs,
        )

    doc.build(story, canvasmaker=_canvas_maker)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Genere la documentation PDF de BahaaIT Network Tools.")
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Chemin cible optionnel pour le PDF genere (defaut: docs/Documentation_BahaaIT_Network_Tools.pdf).",
    )
    args = parser.parse_args()
    out_path = generate_documentation_pdf(args.output)
    size_kb = out_path.stat().st_size / 1024.0
    print(f"[BahaaIT Docs] PDF genere avec succes : {out_path} ({size_kb:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
