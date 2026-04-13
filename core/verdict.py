"""
ClusterIQ — Noise verdict engine.

Verdicts:
  "suppressed" — high similarity, no anomalous context.
                 Safe to suppress as known-good noise.
  "review"     — some anomalous context (off-hours, elevated rate,
                 occasional rare user). Warrants manual review.
  "escalate"   — strong anomalous context: TI indicators, unknown/rare
                 users, or critical assets. Requires immediate attention.

CRITICAL INVARIANT:
  Two clusters with identical signal fingerprints MUST NOT both be
  "suppressed" if one has TI tags or an unknown user.
  Context OVERRIDES signal similarity in the verdict logic below.
"""

from __future__ import annotations


# ── Thresholds ────────────────────────────────────────────────────────────────

# Escalation thresholds
_ESC_USER_THRESH   = 0.65  # user_anomaly ≥ this → escalate
_ESC_ASSET_THRESH  = 0.65  # asset_risk    ≥ this → escalate

# Review thresholds
_REV_TIME_THRESH   = 0.30  # time_anomaly  ≥ this → review
_REV_USER_THRESH   = 0.20  # user_anomaly  ≥ this → review
_REV_ASSET_THRESH  = 0.30  # asset_risk    ≥ this → review
_REV_HITRATE_THRESH= 0.40  # hit_rate_anomaly ≥ this → review

# Minimum weighted review score to promote suppressed → review
_REVIEW_SCORE_MIN  = 0.25


def assign_verdict(
    context:    dict,
    similarity: float,
) -> tuple[str, str, float]:
    """
    Assign a noise verdict from context scores.

    Args:
        context:    output of score_cluster_context()
        similarity: intra-cluster similarity score (0–1)

    Returns:
        (verdict, reason_string, total_context_score)
        verdict ∈ {"suppressed", "review", "escalate"}
    """
    reasons:        list[str] = []
    escalate_score: float     = 0.0
    review_score:   float     = 0.0

    # ── Hard escalation triggers ──────────────────────────────────────────────

    # TI indicator — ALWAYS escalates regardless of similarity
    if context.get("ti_tags"):
        n = context.get("ti_member_count", 1)
        escalate_score += 1.0
        reasons.append(f"threat-intel indicator present ({n} member(s))")

    # Critical asset at escalation level
    ar = context.get("asset_risk", 0.0)
    if context.get("has_critical_asset") and ar >= _ESC_ASSET_THRESH:
        escalate_score += ar
        reasons.append(f"critical asset (risk score {ar:.0%})")
    elif context.get("has_critical_asset") and ar >= _REV_ASSET_THRESH:
        review_score += ar * 0.8
        reasons.append(f"elevated asset risk ({ar:.0%})")

    # Rare / unknown user at escalation level
    ua = context.get("user_anomaly", 0.0)
    if ua >= _ESC_USER_THRESH:
        escalate_score += ua
        n_rare = context.get("unique_users", 0)
        reasons.append(f"unknown/rare user activity (anomaly {ua:.0%}, {n_rare} user(s))")
    elif ua >= _REV_USER_THRESH:
        review_score += ua * 0.7
        reasons.append(f"uncommon user pattern ({ua:.0%})")

    # ── Soft review triggers ──────────────────────────────────────────────────

    # Off-hours activity
    ta = context.get("time_anomaly", 0.0)
    if ta >= _REV_TIME_THRESH:
        off = context.get("off_hours_count", 0)
        review_score += ta * 0.6
        reasons.append(f"off-hours activity ({off} alert(s) outside business hours)")

    # Elevated hit rate
    hr = context.get("hit_rate_anomaly", 0.0)
    if hr >= _REV_HITRATE_THRESH:
        review_score += hr * 0.4
        reasons.append(f"elevated hit rate (anomaly {hr:.0%})")

    # ── Verdict decision ──────────────────────────────────────────────────────

    total_score = round(escalate_score + review_score, 3)

    if escalate_score > 0:
        verdict = "escalate"
    elif review_score >= _REVIEW_SCORE_MIN:
        verdict = "review"
    else:
        verdict = "suppressed"

    if not reasons:
        reason = "no anomalous context — matches expected baseline behaviour"
    else:
        reason = "; ".join(reasons)

    return verdict, reason, total_score
