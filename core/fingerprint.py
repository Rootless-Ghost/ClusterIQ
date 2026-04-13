"""
ClusterIQ — Alert fingerprinting and similarity scoring.

Builds a fingerprint dict from selected ECS-lite fields, then computes
a token-level Jaccard similarity between two fingerprints for fuzzy
cluster merging.
"""

import hashlib
import re
from typing import Any


def _get_nested(obj: dict, path: str) -> Any:
    """Retrieve a value from a nested dict using a dot-notation path."""
    val = obj
    for part in path.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(part)
    return val


def build_fingerprint(alert: dict, cluster_by: list[str]) -> dict:
    """
    Extract fingerprinting fields from an alert.

    Returns a dict of {field: normalized_value_str} for every cluster_by
    field that is present and non-null in the alert.
    """
    fp: dict[str, str] = {}
    for field in cluster_by:
        val = _get_nested(alert, field)
        if val is not None and str(val).strip():
            fp[field] = str(val).lower().strip()
    return fp


def fingerprint_hash(fp: dict) -> str:
    """Produce a stable 16-character hex hash from a fingerprint dict."""
    parts    = [f"{k}={v}" for k, v in sorted(fp.items())]
    combined = "|".join(parts)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def _tokenize(s: str) -> set[str]:
    """Split a field value into tokens for fuzzy comparison."""
    tokens = re.split(r"[\s/\\.,;:\-_()]+", s.lower())
    return {t for t in tokens if len(t) > 1}


def similarity_score(fp1: dict, fp2: dict) -> float:
    """
    Compute similarity between two fingerprints.

    For each field present in either fingerprint:
      - Both missing → 1.0 (not a differentiator)
      - One missing  → 0.0 (structural mismatch)
      - Both present, equal → 1.0
      - Both present, different → token-level Jaccard similarity

    Returns the average field score in [0.0, 1.0].
    """
    all_fields = set(fp1.keys()) | set(fp2.keys())
    if not all_fields:
        return 0.0

    scores: list[float] = []
    for field in all_fields:
        v1 = fp1.get(field)
        v2 = fp2.get(field)

        if v1 is None and v2 is None:
            scores.append(1.0)
        elif v1 is None or v2 is None:
            scores.append(0.0)
        elif v1 == v2:
            scores.append(1.0)
        else:
            t1 = _tokenize(v1)
            t2 = _tokenize(v2)
            if not t1 and not t2:
                scores.append(0.0)
            elif not t1 or not t2:
                scores.append(0.0)
            else:
                inter = len(t1 & t2)
                union = len(t1 | t2)
                scores.append(inter / union)

    return round(sum(scores) / len(scores), 4)
