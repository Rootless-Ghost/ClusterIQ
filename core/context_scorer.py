"""
ClusterIQ — Context scoring for alert clusters.

Scores each cluster across five contextual dimensions:
  - ti_tags:          threat-intel indicator present in any member
  - has_critical_asset: any member involves a high-value host
  - user_anomaly:     rare / unknown users relative to session baseline
  - asset_risk:       fraction of members involving critical assets
  - time_anomaly:     fraction of members outside business hours
  - hit_rate_anomaly: cluster size relative to session average

IMPORTANT: These scores are inputs to the verdict engine. A cluster
with identical signal fingerprints to another MUST be treated
differently if ti_tags=True or user_anomaly is high.
"""

import re
from datetime import datetime
from typing import Any


# ── Pattern matchers ──────────────────────────────────────────────────────────

_TI_PATTERNS = re.compile(
    r"(threat[_\-\.]intel|threat[_\-\.]indicator|ioc[_\-\.]|misp[_\-\.]|"
    r"stix[_\-\.]|malicious|indicator[_\-\.]|crowdstrike|virustotal|"
    r"abuse\.ch|\bc2(?:\b|[_\-\.])|command.and.control|apt[_\-\.]|ransomware|"
    r"phishing|exploit|trojan|backdoor|spyware|keylogger|"
    r"lateral.movement|exfiltration|persistence|\bti[_\-\.])",
    re.IGNORECASE,
)

_CRITICAL_HOST_PATTERNS = re.compile(
    r"(^dc[\-_]|domain.?controller|exchange|\\bsql\\b|^prod[\-_]|"
    r"^srv[\-_]|^server[\-_]|critical|^sec[\-_]|^pam[\-_]|^vault|"
    r"^ad[\-_]|^ldap|backup|mgmt|^core[\-_]|^infra)",
    re.IGNORECASE,
)

# Business hours: Mon–Fri, 09:00–17:00
_BIZ_START = 9
_BIZ_END   = 17
_BIZ_DAYS  = {0, 1, 2, 3, 4}  # Monday–Friday


# ── Field extraction helpers ──────────────────────────────────────────────────

def _get(obj: dict, path: str) -> Any:
    val = obj
    for part in path.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(part)
    return val


def _extract_tags(alert: dict) -> list[str]:
    """Collect all tag-like string values from an alert."""
    tags: list[str] = []

    for field in ("tags", "rule.tags", "labels"):
        v = _get(alert, field)
        if isinstance(v, list):
            tags.extend(str(x) for x in v)
        elif isinstance(v, str):
            tags.append(v)

    # threat.indicator subtree
    threat = alert.get("threat", {})
    if isinstance(threat, dict):
        indicator = threat.get("indicator", {})
        if isinstance(indicator, dict):
            for v in indicator.values():
                if isinstance(v, str):
                    tags.append(v)

    # event.category / event.type / event.kind / event.outcome
    for f in ("event.category", "event.type", "event.kind", "event.outcome"):
        v = _get(alert, f)
        if isinstance(v, str):
            tags.append(v)
        elif isinstance(v, list):
            tags.extend(str(x) for x in v)

    return tags


def _has_ti_indicators(alert: dict) -> bool:
    """Return True if the alert contains any threat-intelligence indicators."""
    for tag in _extract_tags(alert):
        if _TI_PATTERNS.search(tag):
            return True

    # Also scan the top-level dict for indicator-like key/value strings
    def _scan(d: dict, depth: int = 0) -> bool:
        if depth > 3:
            return False
        for k, v in d.items():
            if isinstance(k, str) and _TI_PATTERNS.search(k):
                return True
            if isinstance(v, str) and _TI_PATTERNS.search(v):
                return True
            if isinstance(v, dict) and _scan(v, depth + 1):
                return True
        return False

    return _scan(alert)


def _is_critical_asset(alert: dict) -> bool:
    """Heuristic: is the involved host a high-value / critical asset?"""
    for field in ("host.name", "host.hostname", "agent.hostname",
                  "destination.domain", "source.domain"):
        val = _get(alert, field)
        if isinstance(val, str) and val:
            if _CRITICAL_HOST_PATTERNS.search(val):
                return True
    return False


def _outside_business_hours(alert: dict) -> bool | None:
    """Return True if outside biz hours, False if inside, None if unknown."""
    for field in ("@timestamp", "timestamp", "event.created", "event.start"):
        val = _get(alert, field)
        if not isinstance(val, str) or not val:
            continue
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.weekday() not in _BIZ_DAYS:
                return True
            if dt.hour < _BIZ_START or dt.hour >= _BIZ_END:
                return True
            return False
        except Exception:
            pass
    return None


def _extract_user(alert: dict) -> str | None:
    for field in ("user.name", "user.id",
                  "winlog.event_data.SubjectUserName", "source.user.name"):
        val = _get(alert, field)
        if isinstance(val, str) and val and val not in ("-", "N/A", "SYSTEM", ""):
            return val.lower()
    return None


def _extract_asset(alert: dict) -> str | None:
    for field in ("host.name", "host.hostname", "agent.name", "source.address"):
        val = _get(alert, field)
        if isinstance(val, str) and val:
            return val.lower()
    return None


# ── Main scorer ───────────────────────────────────────────────────────────────

def score_cluster_context(
    members:              list[dict],
    all_session_alerts:   list[dict],
    avg_cluster_size:     float,
    session_user_counts:  dict[str, int],
) -> dict:
    """
    Compute contextual anomaly scores for a cluster.

    Returns:
        {
          "ti_tags":            bool   — any TI indicator in any member
          "has_critical_asset": bool   — any critical asset present
          "user_anomaly":       float  — 0.0–1.0
          "asset_risk":         float  — 0.0–1.0
          "time_anomaly":       float  — 0.0–1.0
          "hit_rate_anomaly":   float  — 0.0–1.0
          "unique_users":       int
          "unique_assets":      int
          "off_hours_count":    int
          "ti_member_count":    int
        }
    """
    if not members:
        return {
            "ti_tags": False, "has_critical_asset": False,
            "user_anomaly": 0.0, "asset_risk": 0.0,
            "time_anomaly": 0.0, "hit_rate_anomaly": 0.0,
            "unique_users": 0, "unique_assets": 0,
            "off_hours_count": 0, "ti_member_count": 0,
        }

    # TI indicators
    ti_members = [m for m in members if _has_ti_indicators(m)]
    ti_tags    = len(ti_members) > 0

    # Critical asset
    critical_members   = [m for m in members if _is_critical_asset(m)]
    has_critical_asset = len(critical_members) > 0
    asset_risk         = round(len(critical_members) / len(members), 3)

    # Time anomaly
    time_checks = [_outside_business_hours(m) for m in members]
    known_checks = [r for r in time_checks if r is not None]
    off_hours    = sum(1 for r in known_checks if r)
    time_anomaly = round(off_hours / len(known_checks), 3) if known_checks else 0.0

    # User anomaly: users that appear rarely across the whole session
    cluster_users = {_extract_user(m) for m in members} - {None}
    total_session  = len(all_session_alerts) or 1

    # A user is "rare" if they appear in ≤ 1% of all session alerts
    rare_threshold = max(2, total_session * 0.01)
    rare_users     = {u for u in cluster_users
                      if session_user_counts.get(u, 0) <= rare_threshold}
    if cluster_users:
        user_anomaly = round(len(rare_users) / len(cluster_users), 3)
    else:
        user_anomaly = 0.05  # no user field — slight uncertainty

    # Assets
    cluster_assets = {_extract_asset(m) for m in members} - {None}

    # Hit rate anomaly
    size = len(members)
    if avg_cluster_size > 0 and size > avg_cluster_size * 1.5:
        ratio           = (size - avg_cluster_size) / max(avg_cluster_size, 1)
        hit_rate_anomaly = round(min(1.0, ratio * 0.25), 3)
    else:
        hit_rate_anomaly = 0.0

    return {
        "ti_tags":            ti_tags,
        "has_critical_asset": has_critical_asset,
        "user_anomaly":       user_anomaly,
        "asset_risk":         asset_risk,
        "time_anomaly":       time_anomaly,
        "hit_rate_anomaly":   hit_rate_anomaly,
        "unique_users":       len(cluster_users),
        "unique_assets":      len(cluster_assets),
        "off_hours_count":    off_hours,
        "ti_member_count":    len(ti_members),
    }
