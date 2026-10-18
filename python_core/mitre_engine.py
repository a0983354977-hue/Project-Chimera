"""MITRE ATT&CK automated TTP mapping and threat intelligence synthesis."""

import html
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "tactic_id": "TA0005"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "tactic_id": "TA0002"},
    "T1204": {"name": "User Execution", "tactic": "Execution", "tactic_id": "TA0002"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "tactic_id": "TA0003"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "tactic_id": "TA0004"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "tactic_id": "TA0005"},
    "T1070": {"name": "Indicator Removal on Host", "tactic": "Defense Evasion", "tactic_id": "TA0005"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "tactic_id": "TA0006"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "tactic_id": "TA0007"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery", "tactic_id": "TA0007"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "tactic_id": "TA0008"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection", "tactic_id": "TA0009"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "tactic_id": "TA0011"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "tactic_id": "TA0011"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "tactic_id": "TA0010"},
}

API_TO_TECHNIQUES: dict[str, list[str]] = {
    "virtualallocex": ["T1055"],
    "writeprocessmemory": ["T1055"],
    "createremotethread": ["T1055"],
    "ntunmapviewofsection": ["T1055"],
    "setthreadcontext": ["T1055"],
    "resumethread": ["T1055"],
    "ntcreatethreadex": ["T1055"],
    "rtlcreatethread": ["T1055"],
    "zwcreatethreadex": ["T1055"],
    "virtualalloc": ["T1055"],
    "internetopenurla": ["T1071"],
    "internetopenurlw": ["T1071"],
    "internetconnecta": ["T1071"],
    "internetconnectw": ["T1071"],
    "httpopenrequesta": ["T1071"],
    "httpopenrequestw": ["T1071"],
    "httpsendrequesta": ["T1071"],
    "httpsendrequestw": ["T1071"],
    "winhttpopen": ["T1071"],
    "winhttpconnect": ["T1071"],
    "winhttpopenrequest": ["T1071"],
    "winhttpsendrequest": ["T1071"],
    "wsasocket": ["T1071"],
    "connect": ["T1071"],
    "send": ["T1071"],
    "recv": ["T1071"],
    "createtoolhelp32snapshot": ["T1057"],
    "process32first": ["T1057"],
    "process32next": ["T1057"],
    "enumprocesses": ["T1057"],
    "ntquerysysteminformation": ["T1057"],
    "lsaenumeratelogonsessions": ["T1003"],
    "lsagetlogonsessiondata": ["T1003"],
    "setwindowshookexa": ["T1547"],
    "setwindowshookexw": ["T1547"],
    "regsetvalueexa": ["T1547"],
    "regsetvalueexw": ["T1547"],
    "findfirstfilea": ["T1083"],
    "findfirstfilew": ["T1083"],
    "findnextfilea": ["T1083"],
    "findnextfilew": ["T1083"],
    "getfileattributesa": ["T1083"],
    "getfileattributesw": ["T1083"],
    "copyfilea": ["T1105"],
    "copyfilew": ["T1105"],
    "movefilea": ["T1105"],
    "movefilew": ["T1105"],
    "urldownloadtofilea": ["T1105"],
    "urldownloadtofilew": ["T1105"],
}

TECHNIQUE_KILL_CHAIN: dict[str, str] = {
    "T1057": "Reconnaissance",
    "T1083": "Reconnaissance",
    "T1003": "Credential Access",
    "T1548": "Exploitation",
    "T1547": "Installation",
    "T1055": "Installation",
    "T1027": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1071": "Command and Control",
    "T1105": "Command and Control",
    "T1005": "Actions on Objectives",
    "T1048": "Actions on Objectives",
    "T1021": "Lateral Movement",
    "T1059": "Execution",
    "T1204": "Execution",
}

KILL_CHAIN_ORDER: list[str] = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

HIGH_CONFIDENCE_COMBINATIONS: list[tuple[tuple[str, ...], str, str]] = [
    (("virtualallocex", "writeprocessmemory", "createremotethread"), "T1055", "Classic DLL/thread process injection; highly consistent with Cobalt Strike stager or remote shellcode loader."),
    (("ntunmapviewofsection", "setthreadcontext", "resumethread"), "T1055", "Process hollowing pattern; replaces legitimate process memory with malicious payload before resuming execution."),
    (("virtualallocex", "writeprocessmemory"), "T1055", "Memory allocation and write into remote process; preparatory stage for remote code execution."),
    (("internetopenurla", "internetopenurlw", "httpsendrequesta", "httpsendrequestw"), "T1071", "HTTP-based command and control channel; consistent with beacon or downloader behavior."),
    (("wsasocket", "connect"), "T1071", "Raw TCP socket connection; indicative of reverse shell or C2 beacon."),
    (("lsaenumeratelogonsessions", "lsagetlogonsessiondata"), "T1003", "LSA logon session enumeration; classic credential dumping precursor (e.g. Mimikatz)."),
    (("setwindowshookexa", "setwindowshookexw"), "T1547", "Window hook installation for persistence; commonly abused by droppers and keyloggers."),
]

STAGER_SIGNATURES: list[tuple[Sequence[str], str]] = [
    (["virtualallocex", "writeprocessmemory", "createremotethread"], "Cobalt Strike Stager or equivalent remote process injector"),
    (["ntunmapviewofsection", "setthreadcontext", "resumethread"], "Process Hollowing loader; suspected staged payload delivery"),
    (["internetopenurla", "createremotethread"], "HTTP downloader with in-memory execution capability"),
    (["lsaenumeratelogonsessions", "createremotethread"], "Credential-theft loader with remote execution"),
]


@dataclass
class MatchedTTP:
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    confidence: float
    matched_apis: list[str] = field(default_factory=list)
    kill_chain_phase: str = "Unknown"
    description: str = ""


@dataclass
class TacticalSummary:
    overall_risk: float
    primary_tactics: list[str]
    primary_techniques: list[str]
    kill_chain_phases: list[str]
    threat_label: str
    confidence: str
    summary_text: str
    ttps: list[MatchedTTP] = field(default_factory=list)


def _normalize_import(name: str) -> str:
    return name.rsplit(".", 1)[-1].casefold()


def map_apis_to_ttps(imports: Sequence[str]) -> list[MatchedTTP]:
    normalized = {_normalize_import(item) for item in imports}
    matched: dict[str, MatchedTTP] = {}

    for api_name in sorted(normalized):
        for technique_id in API_TO_TECHNIQUES.get(api_name, []):
            info = TECHNIQUE_DB[technique_id]
            if technique_id not in matched:
                matched[technique_id] = MatchedTTP(
                    technique_id=technique_id,
                    technique_name=info["name"],
                    tactic=info["tactic"],
                    tactic_id=info["tactic_id"],
                    confidence=0.0,
                    kill_chain_phase=TECHNIQUE_KILL_CHAIN.get(technique_id, "Unknown"),
                )
            matched[technique_id].matched_apis.append(api_name)

    for technique_id, ttp in matched.items():
        api_count = len(ttp.matched_apis)
        base = min(0.4 + 0.15 * api_count, 0.95)
        ttp.confidence = round(base, 2)

    for apis, technique_id, description in HIGH_CONFIDENCE_COMBINATIONS:
        if all(api in normalized for api in apis):
            if technique_id in matched:
                matched[technique_id].confidence = min(matched[technique_id].confidence + 0.2, 0.99)
                matched[technique_id].description = description

    for apis, label in STAGER_SIGNATURES:
        if all(api in normalized for api in apis):
            pass

    return sorted(matched.values(), key=lambda t: (-t.confidence, t.technique_id))


def _select_threat_label(ttps: list[MatchedTTP], yara_matches: Sequence[dict]) -> str:
    api_set = set()
    for ttp in ttps:
        api_set.update(ttp.matched_apis)

    for apis, label in STAGER_SIGNATURES:
        if all(api in api_set for api in apis):
            return label

    tactics = {ttp.tactic for ttp in ttps}
    if "Credential Access" in tactics and "Defense Evasion" in tactics:
        return "Multi-stage credential-theft implant"
    if "Command and Control" in tactics and "Defense Evasion" in tactics:
        return "C2 beacon with injection capability"
    if "Defense Evasion" in tactics:
        return "Defense evasion toolkit"
    if "Persistence" in tactics:
        return "Persistence mechanism"
    if "Discovery" in tactics:
        return "Reconnaissance utility"
    if yara_matches:
        return "YARA-matched suspicious binary"
    return "Low-confidence triage signal"


def build_tactical_summary(
    risk_score: float,
    ttps: list[MatchedTTP],
    yara_matches: Sequence[dict] | None = None,
    sections: Sequence[str] | None = None,
    imports: Sequence[str] | None = None,
) -> TacticalSummary:
    yara_matches = yara_matches or []
    sections = sections or []
    imports = imports or []

    tactics: list[str] = []
    for ttp in ttps:
        if ttp.tactic not in tactics:
            tactics.append(ttp.tactic)

    techniques = [ttp.technique_name for ttp in ttps]
    phases: list[str] = []
    for ttp in ttps:
        if ttp.kill_chain_phase not in phases:
            phases.append(ttp.kill_chain_phase)

    ordered_phases = [p for p in KILL_CHAIN_ORDER if p in phases]
    remaining = [p for p in phases if p not in ordered_phases]
    ordered_phases.extend(remaining)

    threat_label = _select_threat_label(ttps, yara_matches)

    if risk_score >= 0.75:
        confidence = "HIGH"
    elif risk_score >= 0.5:
        confidence = "MEDIUM"
    elif risk_score >= 0.25:
        confidence = "LOW"
    else:
        confidence = "MINIMAL"

    tactic_list = ", ".join(tactics) if tactics else "none identified"
    technique_list = ", ".join(techniques) if techniques else "none identified"
    phase_list = " → ".join(ordered_phases) if ordered_phases else "none identified"

    if risk_score >= 0.75 and ttps:
        summary_text = (
            f"[!] ALERT: {threat_label}. Risk score {risk_score:.3f}. "
            f"Detected techniques: {technique_list}. Tactics: {tactic_list}. "
            f"Kill chain: {phase_list}. Immediate triage recommended."
        )
    elif risk_score >= 0.5 and ttps:
        summary_text = (
            f"[!] WARNING: {threat_label}. Risk score {risk_score:.3f}. "
            f"Techniques: {technique_list}. Tactics: {tactic_list}. "
            f"Kill chain: {phase_list}. Review recommended."
        )
    elif ttps:
        summary_text = (
            f"[!] NOTICE: {threat_label}. Risk score {risk_score:.3f}. "
            f"Techniques: {technique_list}. Tactics: {tactic_list}. "
            f"Kill chain: {phase_list}. Monitor for further activity."
        )
    else:
        summary_text = (
            f"[!] INFO: No MITRE ATT&CK techniques mapped. Risk score {risk_score:.3f}. "
            f"No actionable TTPs identified from static imports."
        )

    if yara_matches:
        rule_names = ", ".join(m.get("rule", "unknown") for m in yara_matches)
        summary_text += f" YARA matches: {rule_names}."

    return TacticalSummary(
        overall_risk=risk_score,
        primary_tactics=tactics,
        primary_techniques=techniques,
        kill_chain_phases=ordered_phases,
        threat_label=threat_label,
        confidence=confidence,
        summary_text=summary_text,
        ttps=ttps,
    )


def reconstruct_kill_chain(ttps: list[MatchedTTP]) -> dict[str, list[MatchedTTP]]:
    chain: dict[str, list[MatchedTTP]] = {phase: [] for phase in KILL_CHAIN_ORDER}
    for ttp in ttps:
        phase = ttp.kill_chain_phase
        if phase in chain:
            chain[phase].append(ttp)
        else:
            chain.setdefault(phase, []).append(ttp)
    return {phase: entries for phase, entries in chain.items() if entries}


def generate_markdown_report(
    file_path: str,
    risk_score: float,
    summary: dict,
    sections: Sequence[dict],
    imports: Sequence[str],
    yara_matches: Sequence[dict],
    architecture: str,
) -> str:
    ttps: Sequence[dict] = summary.get("ttps", [])
    lines: list[str] = []
    lines.append("# Chimera Threat Intelligence Report")
    lines.append("")
    lines.append(f"**Target:** `{html.escape(file_path)}`")
    lines.append(f"**Architecture:** {architecture}")
    lines.append(f"**Risk Score:** {risk_score:.3f}")
    lines.append(f"**Confidence:** {summary.get('confidence', 'UNKNOWN')}")
    lines.append(f"**Threat Label:** {html.escape(summary.get('threat_label', 'Unknown'))}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(summary.get("summary_text", ""))
    lines.append("")
    lines.append("## MITRE ATT&CK TTP Mapping")
    lines.append("")
    lines.append("| Technique | Tactic | Kill Chain Phase | Confidence | Matched APIs |")
    lines.append("|-----------|--------|------------------|------------|--------------|")
    for ttp in ttps:
        apis = ", ".join(ttp.get("matched_apis", [])) if ttp.get("matched_apis") else "—"
        lines.append(
            f"| {ttp.get('technique_id', '?')} — {html.escape(ttp.get('technique_name', '?'))} | "
            f"{html.escape(ttp.get('tactic', '?'))} ({ttp.get('tactic_id', '?')}) | "
            f"{ttp.get('kill_chain_phase', 'Unknown')} | {ttp.get('confidence', 0):.2f} | {apis} |"
        )
    if not ttps:
        lines.append("| — | — | — | — | No techniques mapped |")
    lines.append("")
    lines.append("## Attack Kill Chain Reconstruction")
    lines.append("")
    chain = reconstruct_kill_chain_from_dicts(ttps)
    for phase in KILL_CHAIN_ORDER:
        entries = chain.get(phase, [])
        if not entries:
            continue
        lines.append(f"### {phase}")
        lines.append("")
        for ttp in entries:
            lines.append(
                f"- **{ttp.get('technique_id', '?')} {html.escape(ttp.get('technique_name', '?'))}** — "
                f"{html.escape(ttp.get('tactic', '?'))} (confidence {ttp.get('confidence', 0):.2f})"
            )
            if ttp.get("description"):
                lines.append(f"  - {html.escape(ttp['description'])}")
        lines.append("")
    lines.append("## File Structure")
    lines.append("")
    lines.append("| Section | Entropy |")
    lines.append("|---------|---------|")
    for section in sections:
        lines.append(f"| {html.escape(section.get('name', '?'))} | {section.get('entropy', 0):.3f} |")
    lines.append("")
    lines.append("## Imports")
    lines.append("")
    lines.append("| Import |")
    lines.append("|------|")
    for imp in imports:
        lines.append(f"| {html.escape(imp)} |")
    lines.append("")
    lines.append("## YARA Matches")
    lines.append("")
    if yara_matches:
        lines.append("| Rule | Namespace | Tags |")
        lines.append("|------|-----------|------|")
        for match in yara_matches:
            tags = ", ".join(match.get("tags", []))
            lines.append(
                f"| {html.escape(match.get('rule', '?'))} | "
                f"{html.escape(match.get('namespace', '?'))} | {tags} |"
            )
    else:
        lines.append("None.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by Project Chimera — MITRE ATT&CK Automated TTP Mapping Engine*")
    return "\n".join(lines)


def reconstruct_kill_chain_from_dicts(ttps: Sequence[dict]) -> dict[str, list[dict]]:
    chain: dict[str, list[dict]] = {phase: [] for phase in KILL_CHAIN_ORDER}
    for ttp in ttps:
        phase = ttp.get("kill_chain_phase", "Unknown")
        if phase in chain:
            chain[phase].append(ttp)
        else:
            chain.setdefault(phase, []).append(ttp)
    return {phase: entries for phase, entries in chain.items() if entries}


def generate_html_report(
    file_path: str,
    risk_score: float,
    summary: dict,
    sections: Sequence[dict],
    imports: Sequence[str],
    yara_matches: Sequence[dict],
    architecture: str,
) -> str:
    ttps: Sequence[dict] = summary.get("ttps", [])
    escaped_path = html.escape(file_path)
    confidence_color = {
        "HIGH": "#c0392b",
        "MEDIUM": "#e67e22",
        "LOW": "#f1c40f",
        "MINIMAL": "#27ae60",
    }.get(summary.get("confidence", "MINIMAL"), "#95a5a6")

    chain = reconstruct_kill_chain_from_dicts(ttps)

    ttp_rows = ""
    for ttp in ttps:
        apis = ", ".join(html.escape(a) for a in ttp.get("matched_apis", [])) if ttp.get("matched_apis") else "—"
        desc = f"<br><small>{html.escape(ttp.get('description', ''))}</small>" if ttp.get("description") else ""
        ttp_rows += (
            "<tr>"
            f"<td><code>{ttp.get('technique_id', '?')}</code></td>"
            f"<td>{html.escape(ttp.get('technique_name', '?'))}</td>"
            f"<td>{html.escape(ttp.get('tactic', '?'))} ({ttp.get('tactic_id', '?')})</td>"
            f"<td>{ttp.get('kill_chain_phase', 'Unknown')}</td>"
            f"<td>{ttp.get('confidence', 0):.2f}</td>"
            f"<td>{apis}</td>"
            f"<td>{desc}</td>"
            "</tr>"
        )
    if not ttps:
        ttp_rows = "<tr><td colspan='7'>No MITRE ATT&CK techniques mapped.</td></tr>"

    chain_html = ""
    for phase in KILL_CHAIN_ORDER:
        entries = chain.get(phase, [])
        if not entries:
            continue
        items = ""
        for ttp in entries:
            items += (
                f"<li><strong>{ttp.get('technique_id', '?')} {html.escape(ttp.get('technique_name', '?'))}</strong> "
                f"— {html.escape(ttp.get('tactic', '?'))} (confidence {ttp.get('confidence', 0):.2f})</li>"
            )
        chain_html += f"<li><strong>{phase}</strong><ul>{items}</ul></li>"

    section_rows = ""
    for section in sections:
        section_rows += (
            f"<tr><td>{html.escape(section.get('name', '?'))}</td>"
            f"<td>{section.get('entropy', 0):.3f}</td></tr>"
        )

    import_rows = ""
    for imp in imports:
        import_rows += f"<li>{html.escape(imp)}</li>"

    yara_rows = ""
    if yara_matches:
        for match in yara_matches:
            tags = ", ".join(html.escape(t) for t in match.get("tags", []))
            yara_rows += (
                f"<tr><td>{html.escape(match.get('rule', '?'))}</td>"
                f"<td>{html.escape(match.get('namespace', '?'))}</td>"
                f"<td>{tags}</td></tr>"
            )
    else:
        yara_rows = "<tr><td colspan='3'>None.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chimera Threat Intelligence Report</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #0b0c10; color: #c5c6c7; }}
.container {{ max-width: 1100px; margin: 40px auto; padding: 0 24px; }}
.header {{ border-bottom: 2px solid #1f2833; padding-bottom: 16px; margin-bottom: 24px; }}
.header h1 {{ margin: 0; color: #66fcf1; font-size: 26px; }}
.meta {{ display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 8px; }}
.meta div {{ background: #1f2833; padding: 8px 14px; border-radius: 6px; border: 1px solid #45a29e; }}
.card {{ background: #1f2833; border: 1px solid #45a29e; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
.card h2 {{ color: #66fcf1; margin-top: 0; border-bottom: 1px solid #45a29e; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ border: 1px solid #45a29e; padding: 8px 10px; text-align: left; font-size: 13px; }}
th {{ background: #45a29e; color: #0b0c10; }}
code {{ background: #0b0c10; padding: 2px 6px; border-radius: 4px; color: #ff6b6b; }}
ul.kill-chain {{ list-style: none; padding-left: 0; }}
ul.kill-chain li {{ margin: 8px 0; padding: 10px; background: #121417; border-left: 3px solid #45a29e; border-radius: 4px; }}
ul.kill-chain li strong {{ color: #66fcf1; }}
ul.kill-chain ul {{ margin-top: 6px; padding-left: 20px; }}
ul.kill-chain ul li {{ background: #0f1115; border-left: 3px solid #66fcf1; color: #c5c6c7; }}
ul.kill-chain ul li strong {{ color: #ffd166; }}
.summary {{ background: #1f2833; border: 1px solid #e67e22; border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
.summary p {{ margin: 0; color: #f1faee; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #1f2833; font-size: 12px; color: #667; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Chimera Threat Intelligence Report</h1>
<div class="meta">
<div><strong>Target:</strong> {escaped_path}</div>
<div><strong>Architecture:</strong> {architecture}</div>
<div><strong>Risk Score:</strong> {risk_score:.3f}</div>
<div><strong>Confidence:</strong> {summary.get('confidence', 'UNKNOWN')}</div>
<div><strong>Threat Label:</strong> {html.escape(summary.get('threat_label', 'Unknown'))}</div>
</div>
</div>

<div class="summary">
<p>{html.escape(summary.get('summary_text', ''))}</p>
</div>

<div class="card">
<h2>MITRE ATT&amp;CK TTP Mapping</h2>
<table>
<thead>
<tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Kill Chain Phase</th><th>Confidence</th><th>Matched APIs</th><th>Description</th></tr>
</thead>
<tbody>{ttp_rows}</tbody>
</table>
</div>

<div class="card">
<h2>Attack Kill Chain Reconstruction</h2>
<ul class="kill-chain">{chain_html}</ul>
</div>

<div class="card">
<h2>File Structure</h2>
<table>
<thead><tr><th>Section</th><th>Entropy</th></tr></thead>
<tbody>{section_rows}</tbody>
</table>
</div>

<div class="card">
<h2>Imports</h2>
<ul>{import_rows}</ul>
</div>

<div class="card">
<h2>YARA Matches</h2>
<table>
<thead><tr><th>Rule</th><th>Namespace</th><th>Tags</th></tr></thead>
<tbody>{yara_rows}</tbody>
</table>
</div>

<div class="footer">
Generated by Project Chimera — MITRE ATT&amp;CK Automated TTP Mapping Engine
</div>
</div>
</body>
</html>"""


def generate_combined_report(
    records: Sequence[dict],
    report_format: str = "markdown",
) -> str:
    """Generate a combined report across multiple analyzed records."""
    if report_format == "html":
        return _generate_combined_html(records)

    parts: list[str] = []
    parts.append("# Chimera Threat Intelligence Report (Combined)")
    parts.append("")
    parts.append(f"**Files analyzed:** {len(records)}")
    parts.append("")

    high_risk = [r for r in records if r.get("status") == "ok" and r.get("analysis", {}).get("risk_score", 0) >= 0.5]
    if high_risk:
        parts.append(f"**High-risk files:** {len(high_risk)}")
        for r in high_risk:
            analysis = r.get("analysis", {})
            summary = analysis.get("tactical_summary", {})
            parts.append(
                f"- `{html.escape(r.get('file_path', '?'))}` — "
                f"risk {analysis.get('risk_score', 0):.3f} — {html.escape(summary.get('threat_label', 'Unknown'))}"
            )
        parts.append("")

    for record in records:
        if record.get("status") != "ok" or "analysis" not in record:
            continue
        analysis = record["analysis"]
        summary = analysis.get("tactical_summary", {})
        ttps = analysis.get("mitre_ttps", [])
        yara = analysis.get("yara_matches", [])
        sections = record.get("sections", [])
        imports = record.get("imports", [])

        parts.append(f"## {html.escape(record.get('file_path', '?'))}")
        parts.append("")
        parts.append(f"- **Architecture:** {record.get('architecture', '?')}")
        parts.append(f"- **Risk Score:** {analysis.get('risk_score', 0):.3f}")
        parts.append(f"- **Confidence:** {summary.get('confidence', 'UNKNOWN')}")
        parts.append(f"- **Threat Label:** {html.escape(summary.get('threat_label', 'Unknown'))}")
        parts.append("")
        parts.append(summary.get("summary_text", ""))
        parts.append("")

        if ttps:
            parts.append("### MITRE ATT&CK Techniques")
            parts.append("")
            parts.append("| Technique | Tactic | Kill Chain Phase | Confidence |")
            parts.append("|-----------|--------|------------------|------------|")
            for ttp in ttps:
                parts.append(
                    f"| {ttp.get('technique_id', '?')} — {html.escape(ttp.get('technique_name', '?'))} | "
                    f"{html.escape(ttp.get('tactic', '?'))} | {ttp.get('kill_chain_phase', 'Unknown')} | "
                    f"{ttp.get('confidence', 0):.2f} |"
                )
            parts.append("")

        if yara:
            parts.append("### YARA Matches")
            parts.append("")
            for match in yara:
                parts.append(f"- {html.escape(match.get('rule', '?'))} ({html.escape(match.get('namespace', '?'))})")
            parts.append("")

        parts.append("---")
        parts.append("")

    return "\n".join(parts)


def _generate_combined_html(records: Sequence[dict]) -> str:
    """Generate a combined HTML report across multiple analyzed records."""
    high_risk = [r for r in records if r.get("status") == "ok" and r.get("analysis", {}).get("risk_score", 0) >= 0.5]

    file_sections = ""
    for record in records:
        if record.get("status") != "ok" or "analysis" not in record:
            continue
        analysis = record["analysis"]
        summary = analysis.get("tactical_summary", {})
        ttps = analysis.get("mitre_ttps", [])
        yara = analysis.get("yara_matches", [])
        sections = record.get("sections", [])
        imports = record.get("imports", [])

        ttp_rows = ""
        for ttp in ttps:
            apis = ", ".join(html.escape(a) for a in ttp.get("matched_apis", [])) if ttp.get("matched_apis") else "—"
            ttp_rows += (
                "<tr>"
                f"<td><code>{ttp.get('technique_id', '?')}</code></td>"
                f"<td>{html.escape(ttp.get('technique_name', '?'))}</td>"
                f"<td>{html.escape(ttp.get('tactic', '?'))} ({ttp.get('tactic_id', '?')})</td>"
                f"<td>{ttp.get('kill_chain_phase', 'Unknown')}</td>"
                f"<td>{ttp.get('confidence', 0):.2f}</td>"
                f"<td>{apis}</td>"
                "</tr>"
            )
        if not ttps:
            ttp_rows = "<tr><td colspan='6'>No MITRE ATT&CK techniques mapped.</td></tr>"

        section_rows = ""
        for section in sections:
            section_rows += (
                f"<tr><td>{html.escape(section.get('name', '?'))}</td>"
                f"<td>{section.get('entropy', 0):.3f}</td></tr>"
            )

        import_rows = ""
        for imp in imports:
            import_rows += f"<li>{html.escape(imp)}</li>"

        yara_rows = ""
        if yara:
            for match in yara:
                tags = ", ".join(html.escape(t) for t in match.get("tags", []))
                yara_rows += (
                    f"<tr><td>{html.escape(match.get('rule', '?'))}</td>"
                    f"<td>{html.escape(match.get('namespace', '?'))}</td>"
                    f"<td>{tags}</td></tr>"
                )
        else:
            yara_rows = "<tr><td colspan='3'>None.</td></tr>"

        file_sections += f"""
<div class="card">
<h2>{html.escape(record.get('file_path', '?'))}</h2>
<p><strong>Architecture:</strong> {record.get('architecture', '?')} |
   <strong>Risk Score:</strong> {analysis.get('risk_score', 0):.3f} |
   <strong>Confidence:</strong> {summary.get('confidence', 'UNKNOWN')} |
   <strong>Threat Label:</strong> {html.escape(summary.get('threat_label', 'Unknown'))}</p>
<p>{html.escape(summary.get('summary_text', ''))}</p>
<h3>MITRE ATT&amp;CK Techniques</h3>
<table>
<thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Kill Chain Phase</th><th>Confidence</th><th>Matched APIs</th></tr></thead>
<tbody>{ttp_rows}</tbody>
</table>
<h3>File Structure</h3>
<table><thead><tr><th>Section</th><th>Entropy</th></tr></thead><tbody>{section_rows}</tbody></table>
<h3>Imports</h3><ul>{import_rows}</ul>
<h3>YARA Matches</h3>
<table><thead><tr><th>Rule</th><th>Namespace</th><th>Tags</th></tr></thead><tbody>{yara_rows}</tbody></table>
</div>
"""

    high_risk_html = ""
    if high_risk:
        items = ""
        for r in high_risk:
            analysis = r.get("analysis", {})
            summary = analysis.get("tactical_summary", {})
            items += (
                f"<li><code>{html.escape(r.get('file_path', '?'))}</code> — "
                f"risk {analysis.get('risk_score', 0):.3f} — "
                f"{html.escape(summary.get('threat_label', 'Unknown'))}</li>"
            )
        high_risk_html = f"<div class='card'><h2>High-Risk Files</h2><ul>{items}</ul></div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chimera Threat Intelligence Report</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #0b0c10; color: #c5c6c7; }}
.container {{ max-width: 1100px; margin: 40px auto; padding: 0 24px; }}
.header {{ border-bottom: 2px solid #1f2833; padding-bottom: 16px; margin-bottom: 24px; }}
.header h1 {{ margin: 0; color: #66fcf1; font-size: 26px; }}
.card {{ background: #1f2833; border: 1px solid #45a29e; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
.card h2 {{ color: #66fcf1; margin-top: 0; border-bottom: 1px solid #45a29e; padding-bottom: 8px; }}
.card h3 {{ color: #ffd166; margin-top: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ border: 1px solid #45a29e; padding: 8px 10px; text-align: left; font-size: 13px; }}
th {{ background: #45a29e; color: #0b0c10; }}
code {{ background: #0b0c10; padding: 2px 6px; border-radius: 4px; color: #ff6b6b; }}
ul {{ list-style: disc; padding-left: 20px; }}
li {{ margin: 4px 0; }}
.footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #1f2833; font-size: 12px; color: #667; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Chimera Threat Intelligence Report</h1>
<p><strong>Files analyzed:</strong> {len(records)}</p>
</div>
{high_risk_html}
{file_sections}
<div class="footer">
Generated by Project Chimera — MITRE ATT&amp;CK Automated TTP Mapping Engine
</div>
</div>
</body>
</html>"""
