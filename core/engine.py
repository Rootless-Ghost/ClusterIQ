"""
ClusterIQ — Clustering Engine.

Orchestrates:
  1. Alert fingerprinting and cluster grouping
  2. Contextual scoring per cluster
  3. Noise verdict assignment (suppressed / review / escalate)
  4. Session persistence
  5. Exact-match deduplication with time-window awareness
  6. Markdown export
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from .clusterer      import cluster_alerts, DEFAULT_CLUSTER_BY
from .context_scorer import score_cluster_context
from .verdict        import assign_verdict
from .storage        import SessionStorage

logger = logging.getLogger("clusteriq.engine")

DEFAULT_THRESHOLD  = 0.75
DEFAULT_WINDOW_SEC = 300


class ClusterEngine:
    """Main engine: clusters alerts, scores context, assigns verdicts."""

    def __init__(self, config: dict):
        self.config  = config
        self.storage = SessionStorage(config.get("db_path", "./clusteriq.db"))
        cl_cfg       = config.get("clustering", {})
        self.default_threshold  = float(cl_cfg.get("default_threshold", DEFAULT_THRESHOLD))
        self.default_cluster_by = list(cl_cfg.get("default_fields", DEFAULT_CLUSTER_BY))
        logger.info(
            "ClusterEngine initialised (threshold=%.2f, fields=%s)",
            self.default_threshold, self.default_cluster_by,
        )

    # ── Primary: cluster ───────────────────────────────────────────────────────

    def cluster(
        self,
        alerts:               list[dict],
        cluster_by:           list[str] | None = None,
        similarity_threshold: float | None      = None,
        label:                str               = "",
        save:                 bool              = True,
    ) -> dict:
        """
        Cluster alerts and assign context-aware verdicts.

        Args:
            alerts:               ECS-lite alert dicts
            cluster_by:           fields to fingerprint (default from config)
            similarity_threshold: 0.0–1.0, higher = stricter grouping
            label:                human-readable session label
            save:                 persist to SQLite

        Returns:
            Full session dict including all clusters with verdicts.
        """
        if cluster_by is None:
            cluster_by = self.default_cluster_by
        if similarity_threshold is None:
            similarity_threshold = self.default_threshold

        started_at = datetime.utcnow().isoformat() + "Z"
        n          = len(alerts)

        logger.info(
            "Clustering %d alerts (fields=%s, threshold=%.2f)",
            n, cluster_by, similarity_threshold,
        )

        raw_clusters = cluster_alerts(alerts, cluster_by, similarity_threshold)
        avg_size     = n / max(len(raw_clusters), 1)

        full_clusters:   list[dict] = []
        suppressed_count = 0
        review_count     = 0
        escalate_count   = 0

        for cl in raw_clusters:
            members = cl["members"]
            ctx     = score_cluster_context(members, alerts, avg_size)
            verdict, reason, ctx_score = assign_verdict(ctx, cl["similarity_score"])

            if verdict == "suppressed":
                suppressed_count += cl["size"]
            elif verdict == "review":
                review_count += cl["size"]
            else:
                escalate_count += cl["size"]

            full_clusters.append({
                **cl,
                # Cap stored members at 50 per cluster to keep session JSON manageable
                "members":        members[:50],
                "context_scores": ctx,
                "noise_verdict":  verdict,
                "verdict_reason": reason,
                "context_score":  ctx_score,
            })

        noise_reduction_pct = round((suppressed_count / max(n, 1)) * 100, 1)

        session = {
            "label":                label or f"Cluster session — {n} alerts",
            "original_count":       n,
            "cluster_count":        len(full_clusters),
            "suppressed_count":     suppressed_count,
            "review_count":         review_count,
            "escalate_count":       escalate_count,
            "noise_reduction_pct":  noise_reduction_pct,
            "similarity_threshold": similarity_threshold,
            "cluster_by":           cluster_by,
            "clusters":             full_clusters,
            "analyzed_at":          started_at,
            "generator":            "ClusterIQ v1.0.0",
        }

        if save and n > 0:
            session = self.storage.save_session(session)

        logger.info(
            "Clustering complete — %d clusters, suppressed=%d, review=%d, escalate=%d",
            len(full_clusters), suppressed_count, review_count, escalate_count,
        )
        return session

    # ── Secondary: deduplicate ─────────────────────────────────────────────────

    def deduplicate(
        self,
        alerts:         list[dict],
        window_seconds: int = DEFAULT_WINDOW_SEC,
    ) -> dict:
        """
        Remove exact-duplicate alerts within a sliding time window.

        Two alerts are duplicates when they share an identical full-content
        SHA-256 hash AND their timestamps are within window_seconds of each other.
        If an alert has no timestamp, it deduplicates against any identical alert.

        Returns:
            {"success": true, "unique": [...], "removed": N, "original": M}
        """
        seen:   dict[str, float] = {}   # hash → last seen epoch
        unique: list[dict]       = []
        removed                  = 0

        for alert in alerts:
            h       = _full_hash(alert)
            ts_epoch = _extract_epoch(alert)
            prev_ts  = seen.get(h)

            if prev_ts is None:
                seen[h] = ts_epoch if ts_epoch is not None else 0.0
                unique.append(alert)
            else:
                if ts_epoch is None:
                    # No timestamp — treat as within-window duplicate
                    removed += 1
                elif ts_epoch - prev_ts <= window_seconds:
                    removed += 1
                    seen[h] = ts_epoch
                else:
                    # Outside window — new occurrence
                    seen[h] = ts_epoch
                    unique.append(alert)

        return {
            "success":  True,
            "unique":   unique,
            "removed":  removed,
            "original": len(alerts),
        }

    # ── Storage proxies ────────────────────────────────────────────────────────

    def get_sessions(self, **kwargs) -> dict:
        return self.storage.list_sessions(**kwargs)

    def get_session(self, session_id: str) -> dict | None:
        return self.storage.get_session(session_id)

    def delete_session(self, session_id: str) -> bool:
        return self.storage.delete_session(session_id)

    # ── Markdown export ────────────────────────────────────────────────────────

    def to_markdown(self, session: dict) -> str:
        ts  = (session.get("analyzed_at") or "")[:10]
        cby = ", ".join(session.get("cluster_by", []))

        lines = [
            f"# ClusterIQ Session — {session.get('label', 'Alert Cluster Analysis')}",
            "",
            f"> **Generated:** {ts}  ",
            f"> **Original alerts:** {session.get('original_count', 0):,}  ",
            f"> **Clusters:** {session.get('cluster_count', 0)}  ",
            f"> **Cluster by:** {cby}  ",
            f"> **Threshold:** {session.get('similarity_threshold', DEFAULT_THRESHOLD):.2f}  ",
            f"> **Noise reduction:** {session.get('noise_reduction_pct', 0):.1f}%  ",
            f"> **Generator:** ClusterIQ v1.0.0",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Original Alerts | {session.get('original_count', 0):,} |",
            f"| Clusters        | {session.get('cluster_count', 0)} |",
            f"| Suppressed      | {session.get('suppressed_count', 0):,} |",
            f"| Review          | {session.get('review_count', 0):,} |",
            f"| Escalate        | {session.get('escalate_count', 0):,} |",
            f"| Noise Reduction | {session.get('noise_reduction_pct', 0):.1f}% |",
            "",
        ]

        for vkey, vlabel, emoji in [
            ("escalate",   "Escalate",   "🔴"),
            ("review",     "Review",     "🟡"),
            ("suppressed", "Suppressed", "⚪"),
        ]:
            vlist = [c for c in session.get("clusters", []) if c.get("noise_verdict") == vkey]
            if not vlist:
                continue
            lines += ["---", "", f"## {emoji} {vlabel} Clusters ({len(vlist)})", ""]
            for c in vlist:
                fp_str = ", ".join(f"{k}={v}" for k, v in (c.get("fingerprint") or {}).items())
                ctx    = c.get("context_scores", {})
                lines += [
                    f"### Cluster {c['cluster_id']} — {fp_str or '(empty fingerprint)'}",
                    "",
                    f"- **Verdict:** {vlabel}",
                    f"- **Size:** {c['size']} alerts",
                    f"- **Similarity:** {c['similarity_score']:.3f}",
                    f"- **Reason:** {c.get('verdict_reason', '')}",
                    f"- **TI Tags:** {'Yes' if ctx.get('ti_tags') else 'No'}",
                    f"- **Critical Asset:** {'Yes' if ctx.get('has_critical_asset') else 'No'}",
                    f"- **Unique Users:** {ctx.get('unique_users', 0)}",
                    f"- **Unique Assets:** {ctx.get('unique_assets', 0)}",
                    f"- **Off-hours alerts:** {ctx.get('off_hours_count', 0)}",
                    "",
                ]

        lines += [
            "---",
            "",
            "*Generated by ClusterIQ v1.0.0 — Rootless-Ghost / Nebula Forge Suite*",
        ]
        return "\n".join(lines)


# ── Private helpers ───────────────────────────────────────────────────────────

def _full_hash(alert: dict) -> str:
    """Stable full-content SHA-256 hash of an alert (for dedup)."""
    try:
        canonical = json.dumps(alert, sort_keys=True, ensure_ascii=False)
    except Exception:
        canonical = repr(sorted(str(alert)))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _extract_epoch(alert: dict) -> float | None:
    """Extract a Unix epoch float from common timestamp fields."""
    for path in ("@timestamp", "timestamp", "event.created"):
        val = alert
        for part in path.split("."):
            if isinstance(val, dict):
                val = val.get(part)
            else:
                val = None
                break
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return dt.replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                pass
        elif isinstance(val, (int, float)):
            return float(val)
    return None
