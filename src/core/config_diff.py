import difflib
import html
import re
from typing import Any, Dict, List

from utils.infra_security import redact_sensitive_text


def detect_line_section(line: str, current_section: str = "SYSTEM") -> str:
    """Classify a configuration line into an architectural section for diff summaries."""
    s = line.strip().lower()
    if not s:
        return current_section
    if s.startswith(("interface ", "config system interface", "edit \"port", "port-name ")):
        return "INTERFACES"
    if s.startswith(("vlan ", "port-vlan", "tagged ", "untagged ", "switchport access vlan", "switchport trunk", "set vlanid")):
        return "VLANS"
    if s.startswith(("router ", "ip route", "config router ", "set gateway", "network ", "ip default-gateway")):
        return "ROUTING"
    if s.startswith((
        "access-list",
        "ip access-list",
        "config firewall ",
        "crypto ",
        "username ",
        "enable ",
        "aaa ",
        "snmp-server ",
        "set allowaccess",
        "permit ",
        "deny ",
    )):
        return "SECURITY"
    if s.startswith(("hostname ", "sysname ", "config system global", "ntp ", "logging ")):
        return "SYSTEM"
    if s in ("!", "end", "next"):
        return current_section
    return current_section


def compute_config_diff(
    text_a: str,
    text_b: str,
    label_a: str = "Baseline",
    label_b: str = "Candidate",
    redact: bool = True,
) -> Dict[str, Any]:
    """Compute redacted unified & side-by-side diffs with section breakdown."""
    safe_a = redact_sensitive_text(text_a or "") if redact else (text_a or "")
    safe_b = redact_sensitive_text(text_b or "") if redact else (text_b or "")

    lines_a = safe_a.splitlines()
    lines_b = safe_b.splitlines()

    unified = "\n".join(
        difflib.unified_diff(lines_a, lines_b, fromfile=label_a, tofile=label_b, lineterm="")
    )

    sm = difflib.SequenceMatcher(None, lines_a, lines_b)
    side_by_side: List[Dict[str, Any]] = []
    changed_sections: Dict[str, Dict[str, int]] = {}
    added_count = 0
    removed_count = 0

    sec_a = "SYSTEM"
    sec_b = "SYSTEM"
    for line in lines_a:
        sec_a = detect_line_section(line, sec_a)

    # Track per-line section context cleanly across opcodes
    sec_map_a: List[str] = []
    cur = "SYSTEM"
    for ln in lines_a:
        cur = detect_line_section(ln, cur)
        sec_map_a.append(cur)

    sec_map_b: List[str] = []
    cur_b = "SYSTEM"
    for ln in lines_b:
        cur_b = detect_line_section(ln, cur_b)
        sec_map_b.append(cur_b)

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                side_by_side.append({
                    "line_a": i1 + k + 1,
                    "text_a": lines_a[i1 + k],
                    "line_b": j1 + k + 1,
                    "text_b": lines_b[j1 + k],
                    "tag": "EQUAL",
                    "section": sec_map_b[j1 + k],
                })
        elif tag == "replace":
            span = max(i2 - i1, j2 - j1)
            for k in range(span):
                la = lines_a[i1 + k] if (i1 + k) < i2 else ""
                lb = lines_b[j1 + k] if (j1 + k) < j2 else ""
                na = (i1 + k + 1) if (i1 + k) < i2 else None
                nb = (j1 + k + 1) if (j1 + k) < j2 else None
                sec = sec_map_b[j1 + k] if nb else sec_map_a[i1 + k]
                if na is not None:
                    removed_count += 1
                    changed_sections.setdefault(sec, {"added": 0, "removed": 0})["removed"] += 1
                if nb is not None:
                    added_count += 1
                    changed_sections.setdefault(sec, {"added": 0, "removed": 0})["added"] += 1
                side_by_side.append({
                    "line_a": na,
                    "text_a": la,
                    "line_b": nb,
                    "text_b": lb,
                    "tag": "CHANGE",
                    "section": sec,
                })
        elif tag == "delete":
            for idx in range(i1, i2):
                sec = sec_map_a[idx]
                removed_count += 1
                changed_sections.setdefault(sec, {"added": 0, "removed": 0})["removed"] += 1
                side_by_side.append({
                    "line_a": idx + 1,
                    "text_a": lines_a[idx],
                    "line_b": None,
                    "text_b": "",
                    "tag": "DEL",
                    "section": sec,
                })
        elif tag == "insert":
            for jdx in range(j1, j2):
                sec = sec_map_b[jdx]
                added_count += 1
                changed_sections.setdefault(sec, {"added": 0, "removed": 0})["added"] += 1
                side_by_side.append({
                    "line_a": None,
                    "text_a": "",
                    "line_b": jdx + 1,
                    "text_b": lines_b[jdx],
                    "tag": "ADD",
                    "section": sec,
                })

    if added_count == 0 and removed_count == 0:
        summary = "No differences detected"
    else:
        secs = ", ".join(sorted(changed_sections.keys())) or "SYSTEM"
        summary = f"+{added_count} added / -{removed_count} removed ({secs})"

    return {
        "label_a": label_a,
        "label_b": label_b,
        "added_lines": added_count,
        "removed_lines": removed_count,
        "changed_sections": changed_sections,
        "diff_summary": summary,
        "unified_diff": unified,
        "side_by_side": side_by_side,
        "has_changes": (added_count + removed_count) > 0,
    }


def export_diff_html(diff_result: Dict[str, Any], dest_path: str) -> None:
    """Export side-by-side visual diff to a standalone dark-mode HTML report."""
    rows_html: List[str] = []
    bg_map = {
        "ADD": "#064E3B",
        "DEL": "#4C0519",
        "CHANGE": "#451A03",
        "EQUAL": "#0F172A",
    }
    for row in diff_result.get("side_by_side", []):
        bg = bg_map.get(row["tag"], "#0F172A")
        la = str(row["line_a"] or "")
        lb = str(row["line_b"] or "")
        ta = html.escape(row["text_a"] or "")
        tb = html.escape(row["text_b"] or "")
        sec = html.escape(row.get("section", ""))
        rows_html.append(
            f"<tr style='background:{bg};'>"
            f"<td class='ln'>{la}</td><td class='code'><pre>{ta}</pre></td>"
            f"<td class='ln'>{lb}</td><td class='code'><pre>{tb}</pre></td>"
            f"<td class='sec'>{sec}</td></tr>"
        )

    doc = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>BahaaIT Config Diff</title>"
        "<style>"
        "body{background:#020617;color:#E2E8F0;font-family:Segoe UI,sans-serif;padding:20px;}"
        "table{width:100%;border-collapse:collapse;font-family:Consolas,monospace;font-size:12px;}"
        "td,th{border:1px solid #1E293B;padding:4px 8px;vertical-align:top;}"
        "pre{margin:0;white-space:pre-wrap;}"
        ".ln{width:46px;color:#64748B;text-align:right;}"
        ".sec{width:95px;color:#94A3B8;font-size:11px;}"
        "</style></head><body>"
        f"<h2>Configuration Visual Diff: {html.escape(diff_result.get('label_a',''))} "
        f"vs {html.escape(diff_result.get('label_b',''))}</h2>"
        f"<p>{html.escape(diff_result.get('diff_summary',''))}</p>"
        "<table><thead><tr><th>#</th><th>Baseline</th><th>#</th><th>Candidate</th><th>Section</th></tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody></table></body></html>"
    )
    with open(dest_path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def export_diff_text(diff_result: Dict[str, Any], dest_path: str) -> None:
    with open(dest_path, "w", encoding="utf-8") as fh:
        fh.write(f"# {diff_result.get('label_a')} vs {diff_result.get('label_b')}\n")
        fh.write(f"# {diff_result.get('diff_summary')}\n\n")
        fh.write(diff_result.get("unified_diff") or "(No differences)")
