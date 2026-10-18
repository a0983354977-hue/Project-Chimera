"""Family correlation and variant attribution via structural similarity."""

import hashlib
import json
import math
import sqlite3
from pathlib import Path
from typing import Sequence

# Bump when the similarity feature set or schema changes.
CORRELATION_VERSION = 1

_SIMILARITY_CONNECTIONS: dict[str, sqlite3.Connection] = {}


def _corr_connection(db_path: str) -> sqlite3.Connection:
    connection = _SIMILARITY_CONNECTIONS.get(db_path)
    if connection is None:
        connection = sqlite3.connect(db_path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS sample_fingerprints ("
            "content_hash TEXT PRIMARY KEY, file_path TEXT NOT NULL, "
            "architecture TEXT NOT NULL, section_profile TEXT NOT NULL, "
            "import_profile TEXT NOT NULL, first_seen TEXT NOT NULL)"
        )
        connection.commit()
        _SIMILARITY_CONNECTIONS[db_path] = connection
    return connection


def _section_profile(sections: Sequence[dict]) -> str:
    profile = []
    for section in sections:
        name = section.get("name", "")
        entropy = float(section.get("entropy", 0.0))
        profile.append(f"{name}:{entropy:.2f}")
    return "|".join(profile)


def _import_profile(imports: Sequence[str]) -> str:
    normalized = sorted(item.rsplit(".", 1)[-1].casefold() for item in imports)
    return ",".join(normalized)


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _entropy_profile_similarity(profile_a: str, profile_b: str) -> float:
    names_a = [p.split(":")[0] for p in profile_a.split("|") if p]
    names_b = [p.split(":")[0] for p in profile_b.split("|") if p]
    return _jaccard(set(names_a), set(names_b))


def correlate_sample(
    db_path: str,
    content_hash: str,
    file_path: str,
    architecture: str,
    sections: Sequence[dict],
    imports: Sequence[str],
    similarity_threshold: float = 0.75,
) -> dict:
    """Compare a sample against historical fingerprints and record it.

    Returns a dict with keys: ``similar`` (bool), ``best_match`` (dict or None),
    ``best_similarity`` (float), ``attribution_hint`` (str or None).
    """
    section_profile = _section_profile(sections)
    import_profile = _import_profile(imports)

    connection = _corr_connection(db_path)

    best_similarity = 0.0
    best_match: dict | None = None

    rows = connection.execute(
        "SELECT content_hash, file_path, architecture, section_profile, "
        "import_profile, first_seen FROM sample_fingerprints"
    ).fetchall()

    new_imports = set(import_profile.split(",")) if import_profile else set()
    for row in rows:
        hist_hash, hist_path, hist_arch, hist_sec_profile, hist_imp_profile, first_seen = row
        if hist_hash == content_hash:
            continue

        sec_sim = _entropy_profile_similarity(section_profile, hist_sec_profile)
        hist_imports = set(hist_imp_profile.split(",")) if hist_imp_profile else set()
        imp_sim = _jaccard(new_imports, hist_imports)

        # Weighted structural similarity: sections 40%, imports 60%.
        similarity = 0.4 * sec_sim + 0.6 * imp_sim

        if similarity > best_similarity:
            best_similarity = similarity
            best_match = {
                "content_hash": hist_hash,
                "file_path": hist_path,
                "architecture": hist_arch,
                "first_seen": first_seen,
                "section_similarity": round(sec_sim, 2),
                "import_similarity": round(imp_sim, 2),
            }

    similar = best_similarity >= similarity_threshold

    attribution_hint = None
    if similar and best_match is not None:
        pct = int(round(best_similarity * 100))
        attribution_hint = (
            f"此樣本與歷史攔截樣本結構相似度高達 {pct}% "
            f"(首次攔截：{best_match['first_seen']})，疑似同家族變種。"
        )

    # Record this sample for future correlation (skip exact duplicate).
    existing = connection.execute(
        "SELECT 1 FROM sample_fingerprints WHERE content_hash = ?", (content_hash,)
    ).fetchone()
    if existing is None:
        import datetime

        connection.execute(
            "INSERT INTO sample_fingerprints "
            "(content_hash, file_path, architecture, section_profile, "
            "import_profile, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (
                content_hash,
                file_path,
                architecture,
                section_profile,
                import_profile,
                datetime.datetime.utcnow().isoformat() + "Z",
            ),
        )
        connection.commit()

    return {
        "similar": similar,
        "best_match": best_match,
        "best_similarity": round(best_similarity, 2),
        "attribution_hint": attribution_hint,
    }
