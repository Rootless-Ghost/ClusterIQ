"""
ClusterIQ — Contextual Alert Clustering Engine

Author:  Rootless-Ghost
Version: 1.0.0
Port:    5009 (default)

Usage:
    python app.py
    python app.py --port 5009
    python app.py --config /path/to/config.yaml --debug
"""

import argparse
import io
import json
import logging
import os

import yaml
from flask import Flask, jsonify, render_template, request, send_file

from core.engine import ClusterEngine

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("clusteriq")

# ── Config ────────────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
    "port":       5009,
    "db_path":    "./clusteriq.db",
    "output_dir": "./output",
    "clustering": {
        "default_threshold": 0.75,
        "default_fields": [
            "process.name",
            "event.action",
            "network.destination.ip",
        ],
        "max_alerts": 50000,
        "auto_save":  True,
    },
    "integrations": {
        "lognorm_url": "http://127.0.0.1:5006",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ── App factory ───────────────────────────────────────────────────────────────

app      = Flask(__name__)
_config: dict         = {}
_engine: ClusterEngine = None  # type: ignore


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config, _engine
    _config = load_config(config_path)
    _engine = ClusterEngine(_config)
    os.makedirs(_config.get("output_dir", "./output"), exist_ok=True)
    return app


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/session/<session_id>")
def session_page(session_id: str):
    session = _engine.get_session(session_id)
    if session is None:
        return render_template("index.html", error=f"Session {session_id!r} not found"), 404
    return render_template("session.html", session=session)


@app.route("/sessions")
def sessions_page():
    return render_template("library.html")


# ── API: health ───────────────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "tool": "clusteriq", "version": "1.0.0"})


# ── API: cluster ──────────────────────────────────────────────────────────────

@app.route("/api/cluster", methods=["POST"])
def api_cluster():
    """
    Cluster a stream of ECS-lite alerts.

    Body (JSON):
      {
        "alerts":                [{...ECS-lite...}],
        "similarity_threshold":  0.75,
        "cluster_by":            ["process.name", "event.action"],
        "label":                 "optional label",
        "save":                  true
      }

    Also accepts alerts_json (raw JSON string) and multipart/form-data.

    Returns:
      {
        "success": true,
        "session_id": "uuid",
        "clusters": [...],
        "original_count": 847,
        "cluster_count":  12,
        "suppressed_count": 821,
        "review_count":    18,
        "escalate_count":  8,
        "noise_reduction_pct": 96.8
      }
    """
    cl_cfg     = _config.get("clustering", {})
    max_alerts = int(cl_cfg.get("max_alerts", 50000))
    auto_save  = bool(cl_cfg.get("auto_save", True))

    content_type = request.content_type or ""

    if "multipart/form-data" in content_type:
        alerts     = _parse_alerts_from_upload()
        threshold  = float(request.form.get("similarity_threshold",
                           cl_cfg.get("default_threshold", 0.75)))
        cluster_by = _parse_cluster_by_from_form()
        label      = request.form.get("label", "").strip()
        save       = request.form.get("save", "true").lower() != "false"
    else:
        body       = request.get_json(silent=True) or {}
        if body.get("alerts_json"):
            alerts = _parse_events_json(body["alerts_json"])
        else:
            alerts = body.get("alerts") or []
        threshold  = float(body.get("similarity_threshold",
                           cl_cfg.get("default_threshold", 0.75)))
        cluster_by = body.get("cluster_by") or cl_cfg.get("default_fields", [])
        label      = str(body.get("label", "")).strip()
        save       = bool(body.get("save", auto_save))

    if not alerts:
        return jsonify({"success": False, "error": "No alerts provided"}), 400
    if len(alerts) > max_alerts:
        alerts = alerts[:max_alerts]
        logger.warning("Alert list truncated to %d", max_alerts)

    try:
        session = _engine.cluster(
            alerts=alerts,
            cluster_by=cluster_by,
            similarity_threshold=threshold,
            label=label,
            save=save,
        )
        return jsonify({
            "success":             True,
            "session_id":          session.get("id"),
            "clusters":            session.get("clusters", []),
            "original_count":      session.get("original_count", 0),
            "cluster_count":       session.get("cluster_count", 0),
            "suppressed_count":    session.get("suppressed_count", 0),
            "review_count":        session.get("review_count", 0),
            "escalate_count":      session.get("escalate_count", 0),
            "noise_reduction_pct": session.get("noise_reduction_pct", 0),
            "label":               session.get("label", ""),
            "analyzed_at":         session.get("analyzed_at", ""),
        })
    except Exception as exc:
        logger.error("Clustering error: %s", exc, exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500


# ── API: deduplicate ──────────────────────────────────────────────────────────

@app.route("/api/deduplicate", methods=["POST"])
def api_deduplicate():
    """
    Remove exact-duplicate alerts within a time window.

    Body: {"alerts": [...], "window_seconds": 300}
    Returns: {"success": true, "unique": [...], "removed": N}
    """
    body = request.get_json(silent=True) or {}
    if body.get("alerts_json"):
        alerts = _parse_events_json(body["alerts_json"])
    else:
        alerts = body.get("alerts") or []
    window = int(body.get("window_seconds", 300))

    if not alerts:
        return jsonify({"success": False, "error": "No alerts provided"}), 400

    result = _engine.deduplicate(alerts, window_seconds=window)
    return jsonify(result)


# ── API: sessions list ────────────────────────────────────────────────────────

@app.route("/api/sessions")
def api_sessions():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    search   = request.args.get("search", "")
    result   = _engine.get_sessions(page=page, per_page=per_page, search=search)
    return jsonify({"success": True, **result})


# ── API: single session ───────────────────────────────────────────────────────

@app.route("/api/session/<session_id>")
def api_session(session_id: str):
    session = _engine.get_session(session_id)
    if session is None:
        return jsonify({"success": False, "error": "Session not found"}), 404
    return jsonify({"success": True, "session": session})


@app.route("/api/session/<session_id>", methods=["DELETE"])
def api_session_delete(session_id: str):
    deleted = _engine.delete_session(session_id)
    if not deleted:
        return jsonify({"success": False, "error": "Session not found"}), 404
    return jsonify({"success": True, "deleted": session_id})


# ── API: export session ───────────────────────────────────────────────────────

@app.route("/api/session/<session_id>/export")
def api_export(session_id: str):
    fmt     = request.args.get("format", "json").lower()
    session = _engine.get_session(session_id)
    if session is None:
        return jsonify({"success": False, "error": "Session not found"}), 404

    ts       = (session.get("analyzed_at") or "")[:10].replace("-", "")
    filename = f"clusteriq_session_{ts}"

    if fmt == "markdown":
        md_bytes = _engine.to_markdown(session).encode("utf-8")
        return send_file(
            io.BytesIO(md_bytes),
            mimetype="text/markdown",
            as_attachment=True,
            download_name=f"{filename}.md",
        )

    json_bytes = json.dumps(session, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{filename}.json",
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_alerts_from_upload() -> list[dict]:
    if "alerts_file" in request.files:
        f = request.files["alerts_file"]
        try:
            return _parse_events_json(f.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning("Failed to parse alerts file: %s", exc)
    elif "alerts_json" in request.form:
        return _parse_events_json(request.form["alerts_json"])
    return []


def _parse_cluster_by_from_form() -> list[str]:
    raw = request.form.get("cluster_by", "")
    if raw:
        return [f.strip() for f in raw.split(",") if f.strip()]
    fields = request.form.getlist("cluster_by_fields")
    return fields or _config.get("clustering", {}).get("default_fields", [])


def _parse_events_json(raw: str) -> list[dict]:
    raw = raw.strip()
    if raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
        except Exception:
            pass
    else:
        events = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                except Exception:
                    pass
        return events
    return []


# ── CLI entry point ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ClusterIQ — Contextual Alert Clustering Engine")
    p.add_argument("--config",    default="config.yaml")
    p.add_argument("--port",      type=int, default=None)
    p.add_argument("--debug",     action="store_true")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    create_app(args.config)
    port = args.port if args.port is not None else int(_config.get("port", 5009))
    logger.info("ClusterIQ starting on http://0.0.0.0:%d", port)
    app.run(debug=args.debug, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
