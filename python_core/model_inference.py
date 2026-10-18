"""Validated, explainable PE triage, MITRE ATT&CK TTP mapping, and optional YARA matching."""

import hashlib
import json
import sqlite3
from math import isfinite
from pathlib import Path
from typing import Sequence

from .analysis_schema import PEFeatureDocument
from .mitre_engine import build_tactical_summary, generate_combined_report, map_apis_to_ttps, reconstruct_kill_chain
from .family_correlation import correlate_sample

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "VirtualAlloc",
    "WriteProcessMemory",
}
UNUSUAL_SECTIONS = {".aspack", ".neolite", ".packed", ".upx"}
HIGH_ENTROPY = 7.2

# Bump when heuristics, TTP mapping, or the result shape change; invalidates cached analyses.
CACHE_VERSION = 1

# Compiled YARA rules keyed by (resolved path, mtime_ns, size) so a directory scan
# compiles each rules file once instead of once per sample.
_RULES_CACHE: dict[tuple[str, int, int], tuple[object, str]] = {}

# sqlite connections keyed by database path (analysis runs on a single thread).
_CACHE_CONNECTIONS: dict[str, sqlite3.Connection] = {}


def infer_threat(
    sections: Sequence[str],
    imports: Sequence[str],
    entropy_scores: Sequence[float],
) -> float:
    """Return a deterministic heuristic risk score in [0, 1]."""
    if len(sections) != len(entropy_scores):
        raise ValueError("section and entropy counts do not match")
    if not all(isinstance(item, str) for item in sections):
        raise TypeError("section names must be strings")
    if not all(isinstance(item, str) for item in imports):
        raise TypeError("imports must be strings")
    if not all(isfinite(float(value)) and 0.0 <= float(value) <= 8.0
               for value in entropy_scores):
        raise ValueError("entropy scores must be finite values in [0, 8]")

    normalized_imports = {item.rsplit(".", 1)[-1].casefold() for item in imports}
    suspicious_count = sum(
        1 for name in SUSPICIOUS_IMPORTS if name.casefold() in normalized_imports
    )
    import_score = min(suspicious_count / 3.0, 1.0)

    high_entropy_count = sum(
        1 for value in entropy_scores if float(value) >= HIGH_ENTROPY
    )
    entropy_score = (
        high_entropy_count / len(entropy_scores) if entropy_scores else 0.0
    )

    unusual_count = sum(
        1 for name in sections if name.casefold() in UNUSUAL_SECTIONS
    )
    section_score = (
        unusual_count / len(sections) if sections else 0.0
    )

    return min(1.0, 0.4 * import_score + 0.4 * entropy_score + 0.2 * section_score)


def _compiled_rules(rules_path: str) -> tuple[object, str]:
    """Compile a rules file at most once per version and return (rules, signature)."""
    rules_file = Path(rules_path)
    if not rules_file.is_file():
        raise FileNotFoundError(f"YARA rules file not found: {rules_file}")
    stat = rules_file.stat()
    key = (str(rules_file.resolve()), stat.st_mtime_ns, stat.st_size)
    cached = _RULES_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        import yara
    except ImportError as error:
        raise RuntimeError(
            "YARA rules were requested but yara-python is not installed"
        ) from error

    rules = yara.compile(filepath=str(rules_file))
    signature = hashlib.sha256(rules_file.read_bytes()).hexdigest()
    _RULES_CACHE[key] = (rules, signature)
    return rules, signature


def _cache_connection(db_path: str) -> sqlite3.Connection:
    connection = _CACHE_CONNECTIONS.get(db_path)
    if connection is None:
        connection = sqlite3.connect(db_path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS analysis_cache ("
            "cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        connection.commit()
        _CACHE_CONNECTIONS[db_path] = connection
    return connection


def _cache_key(content_hash: str, rules_signature: str, schema_version: int) -> str:
    material = f"{CACHE_VERSION}|{schema_version}|{content_hash}|{rules_signature}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_lookup(db_path: str, cache_key: str) -> str | None:
    row = _cache_connection(db_path).execute(
        "SELECT payload FROM analysis_cache WHERE cache_key = ?", (cache_key,)
    ).fetchone()
    return row[0] if row else None


def _cache_store(db_path: str, cache_key: str, payload: str) -> None:
    connection = _cache_connection(db_path)
    connection.execute(
        "INSERT OR REPLACE INTO analysis_cache (cache_key, payload) VALUES (?, ?)",
        (cache_key, payload),
    )
    connection.commit()


def analyze_feature_json(
    feature_json: str, rules_path: str = "", cache_db_path: str = "",
    corr_db_path: str = ""
) -> str:
    """Validate Nim's JSON document, run heuristics and optional supplied YARA rules.

    When a cache database and a content fingerprint are supplied, an identical
    file/rules/engine combination is answered from the incremental cache.
    """
    document = PEFeatureDocument.model_validate_json(feature_json)

    compiled_rules: object | None = None
    rules_signature = "none"
    if rules_path:
        compiled_rules, rules_signature = _compiled_rules(rules_path)

    cache_key = ""
    if cache_db_path and document.content_hash:
        cache_key = _cache_key(
            document.content_hash, rules_signature, document.schema_version
        )
        cached = _cache_lookup(cache_db_path, cache_key)
        if cached is not None:
            return cached

    risk_score = infer_threat(
        [section.name for section in document.sections],
        document.imports,
        [section.entropy for section in document.sections],
    )

    yara_matches: list[dict[str, object]] = []
    if compiled_rules is not None:
        yara_matches = [
            {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
            }
            for match in compiled_rules.match(filepath=document.file_path)
        ]

    ttps = map_apis_to_ttps(document.imports)
    summary = build_tactical_summary(
        risk_score=risk_score,
        ttps=ttps,
        yara_matches=yara_matches,
        sections=[section.name for section in document.sections],
        imports=document.imports,
    )
    kill_chain = reconstruct_kill_chain(ttps)

    ttps_output = [
        {
            "technique_id": ttp.technique_id,
            "technique_name": ttp.technique_name,
            "tactic": ttp.tactic,
            "tactic_id": ttp.tactic_id,
            "confidence": ttp.confidence,
            "matched_apis": ttp.matched_apis,
            "kill_chain_phase": ttp.kill_chain_phase,
            "description": ttp.description,
        }
        for ttp in ttps
    ]

    summary_output = {
        "overall_risk": summary.overall_risk,
        "primary_tactics": summary.primary_tactics,
        "primary_techniques": summary.primary_techniques,
        "kill_chain_phases": summary.kill_chain_phases,
        "threat_label": summary.threat_label,
        "confidence": summary.confidence,
        "summary_text": summary.summary_text,
    }

    kill_chain_output = {
        phase: [
            {
                "technique_id": ttp.technique_id,
                "technique_name": ttp.technique_name,
                "tactic": ttp.tactic,
                "tactic_id": ttp.tactic_id,
                "confidence": ttp.confidence,
                "matched_apis": ttp.matched_apis,
                "description": ttp.description,
            }
            for ttp in entries
        ]
        for phase, entries in kill_chain.items()
    }

    family_correlation = {}
    if corr_db_path and document.content_hash:
        family_correlation = correlate_sample(
            db_path=corr_db_path,
            content_hash=document.content_hash,
            file_path=document.file_path,
            architecture=document.architecture,
            sections=[
                {"name": section.name, "entropy": section.entropy}
                for section in document.sections
            ],
            imports=document.imports,
        )

    payload = json.dumps(
        {
            "risk_score": risk_score,
            "yara_matches": yara_matches,
            "mitre_ttps": ttps_output,
            "tactical_summary": summary_output,
            "kill_chain": kill_chain_output,
            "family_correlation": family_correlation,
        },
        ensure_ascii=False,
        allow_nan=False,
    )
    if cache_key:
        _cache_store(cache_db_path, cache_key, payload)
    return payload


def generate_report(records_json: str, report_format: str = "markdown") -> str:
    """Generate a combined threat intelligence report from analysis records JSON."""
    records = json.loads(records_json)
    if isinstance(records, dict):
        records = records.get("results", [])
    return generate_combined_report(records, report_format=report_format)
