"""
ClusterIQ — SQLite storage layer for clustering sessions.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime

logger = logging.getLogger("clusteriq.storage")


class SessionStorage:
    """Manages the SQLite database for saved clustering sessions."""

    def __init__(self, db_path: str = "./clusteriq.db"):
        self.db_path = db_path
        self._init_db()

    # ── Connection ─────────────────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id                  TEXT PRIMARY KEY,
                    label               TEXT NOT NULL DEFAULT '',
                    original_count      INTEGER NOT NULL DEFAULT 0,
                    cluster_count       INTEGER NOT NULL DEFAULT 0,
                    suppressed_count    INTEGER NOT NULL DEFAULT 0,
                    review_count        INTEGER NOT NULL DEFAULT 0,
                    escalate_count      INTEGER NOT NULL DEFAULT 0,
                    noise_reduction_pct REAL    NOT NULL DEFAULT 0,
                    session_json        TEXT    NOT NULL,
                    created_at          TEXT    NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_created
                ON sessions (created_at)
            """)
            conn.commit()
        logger.info("Storage initialised: %s", self.db_path)

    # ── Write ──────────────────────────────────────────────────────────────────

    def save_session(self, session: dict) -> dict:
        """Persist a clustering session. Generates a UUID; returns updated session."""
        session_id = str(uuid.uuid4())
        now        = datetime.utcnow().isoformat() + "Z"

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (id, label, original_count, cluster_count,
                     suppressed_count, review_count, escalate_count,
                     noise_reduction_pct, session_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
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
            conditions.append("LOWER(label) LIKE LOWER(?)")
            params.append(f"%{search}%")

        where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        offset = (page - 1) * per_page

        with self._get_conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM sessions {where}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, label, original_count, cluster_count,
                       suppressed_count, review_count, escalate_count,
                       noise_reduction_pct, created_at
                FROM sessions {where}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()

        return {
            "items":    [dict(r) for r in rows],
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, (total + per_page - 1) // per_page),
        }

    # ── Delete ─────────────────────────────────────────────────────────────────

    def delete_session(self, session_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
        return cur.rowcount > 0

    def clear_all(self) -> int:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM sessions")
            conn.commit()
        return cur.rowcount
