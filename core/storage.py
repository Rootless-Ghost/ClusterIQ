"""
ClusterIQ — PostgreSQL storage layer for clustering sessions.

Schema is managed externally via init-db/. Table expected: clusteriq_sessions
"""

import json
import logging
import os
import uuid
from datetime import datetime

import psycopg2
import psycopg2.extras

logger = logging.getLogger("clusteriq.storage")


class SessionStorage:

    def __init__(self, db_path: str = "./clusteriq.db"):
        self._url = os.environ.get("DATABASE_URL") or db_path

    def _get_conn(self):
        return psycopg2.connect(self._url)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_session(self, session: dict) -> dict:
        session_id = str(uuid.uuid4())
        now        = datetime.utcnow().isoformat() + "Z"

        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO clusteriq_sessions
                        (id, label, original_count, cluster_count,
                         suppressed_count, review_count, escalate_count,
                         noise_reduction_pct, session_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        session_id,
                        session.get("label", ""),
                        session.get("original_count", 0),
                        session.get("cluster_count", 0),
                        session.get("suppressed_count", 0),
                        session.get("review_count", 0),
                        session.get("escalate_count", 0),
                        session.get("noise_reduction_pct", 0.0),
                        json.dumps(session),
                        now,
                    ),
                )
            conn.commit()

        session["id"]         = session_id
        session["created_at"] = now
        logger.info("Saved session %s (%d clusters)", session_id, session.get("cluster_count", 0))
        return session

    # ── Read ───────────────────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> dict | None:
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM clusteriq_sessions WHERE id = %s", (session_id,)
                )
                row = cur.fetchone()
        if row is None:
            return None
        data               = json.loads(row["session_json"])
        data["id"]         = row["id"]
        data["created_at"] = row["created_at"]
        return data

    def list_sessions(
        self,
        page:     int = 1,
        per_page: int = 50,
        search:   str = "",
    ) -> dict:
        conditions: list[str] = []
        params:     list      = []

        if search:
            conditions.append("LOWER(label) LIKE LOWER(%s)")
            params.append(f"%{search}%")

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) FROM clusteriq_sessions {where}", params)
                total = cur.fetchone()["count"]
                cur.execute(
                    f"""
                    SELECT id, label, original_count, cluster_count,
                           suppressed_count, review_count, escalate_count,
                           noise_reduction_pct, created_at
                    FROM clusteriq_sessions {where}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [per_page, offset],
                )
                items = [dict(r) for r in cur.fetchall()]

        return {
            "items":    items,
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_session(self, session_id: str) -> bool:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM clusteriq_sessions WHERE id = %s", (session_id,)
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM clusteriq_sessions")
                count = cur.rowcount
            conn.commit()
        return count
