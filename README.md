<div align="center">

# ClusterIQ — Contextual Alert Clustering Engine

Part of the **Nebula Forge** security tools suite.

ClusterIQ groups ECS-lite alerts by signal fingerprint, then scores each cluster
contextually to determine whether it should be **escalated**, **reviewed**, or
**suppressed** as noise. Unlike naive deduplication, ClusterIQ never suppresses
a cluster solely because its signals match — context always wins.

![version](https://img.shields.io/badge/version-v1.0.0-blueviolet?style=flat-square) ![port](https://img.shields.io/badge/port-5006-5d5d5d?style=flat-square) ![python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python) ![framework](https://img.shields.io/badge/framework-Flask-000000?style=flat-square&logo=flask) ![part%20of](https://img.shields.io/badge/part%20of-Nebula%20Forge-7c3aed?style=flat-square) ![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

## Pipeline Position

![Nebula Forge pipeline — LogNorm highlighted](docs/pipeline.svg)

> **purple-loop:** `AtomicLoop → LogNorm → ClusterIQ → HuntForge → DriftWatch → repeat`

---

## Screenshots


![ClusterIQ-Dashboard](docs/screenshots/upload-normalize.png)


![Cluster-Generation](docs/screenshots/upload-normalize.png)

---

## Core Differentiator

Two alerts with **identical signals** (same process name, same destination IP,
same event action) receive **different verdicts** if one carries a TI tag or
involves a rare user:

```
Cluster A — powershell.exe / C2_IP  →  ESCALATE  (TI indicator present)
Cluster B — powershell.exe / C2_IP  →  REVIEW    (off-hours, rare user)
Cluster C — powershell.exe / C2_IP  →  SUPPRESSED (known user, business hours, no TI)
```

---

## Features

- **Signal fingerprinting** — configurable cluster-by fields (process.name, event.action, destination IP, etc.)
- **Fuzzy cluster merging** — token-level Jaccard similarity above a configurable threshold
- **Five context dimensions** — TI indicators, critical asset heuristic, user anomaly, time-of-day, hit rate
- **Context-first verdict engine** — TI tags always escalate regardless of similarity score
- **Exact deduplication** — `/api/deduplicate` with sliding time-window
- **Session library** — persistent SQLite storage, search, pagination, export
- **Export** — JSON and Markdown per session
- **CLI** — offline analysis without the web UI
- **Integration** — accepts ECS-lite directly from LogNorm (port 5006)

---

## Quick Start

```bash
cd ClusterIQ
pip install -r requirements.txt
cp config.example.yaml config.yaml   # optional
python app.py
```

Open [http://127.0.0.1:5009](http://127.0.0.1:5009).

---

## Usage

### Web UI

1. Paste or upload ECS-lite alerts (JSON array or NDJSON).
2. Check the fields to cluster by, set the similarity threshold.
3. Click **Cluster Alerts**.
4. Results appear as color-coded cluster cards:
   - **Red** — Escalate
   - **Yellow** — Review
   - **Grey** — Suppressed
5. Click any card to open the detail modal (Overview, Context Scores, Members).

### CLI

```bash
# Cluster alerts, print summary
python cli.py --alerts alerts.json

# Custom fields and threshold
python cli.py --alerts alerts.json --fields process.name,event.action --threshold 0.8

# Save output as Markdown
python cli.py --alerts alerts.json --output session.md

# Deduplicate with 5-minute window
python cli.py --dedup --alerts alerts.json --window 300

# Print as JSON
python cli.py --alerts alerts.json --format json
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/health`                        | Health check |
| POST   | `/api/cluster`                       | Cluster alerts |
| POST   | `/api/deduplicate`                   | Remove exact duplicates |
| GET    | `/api/sessions`                      | List sessions (paginated) |
| GET    | `/api/session/<id>`                  | Get a single session |
| DELETE | `/api/session/<id>`                  | Delete a session |
| GET    | `/api/session/<id>/export`           | Export (JSON or Markdown) |

### POST /api/cluster

```json
{
  "alerts":               [{...ECS-lite...}],
  "similarity_threshold": 0.75,
  "cluster_by":           ["process.name", "event.action", "network.destination.ip"],
  "label":                "Monday SOC triage",
  "save":                 true
}
```

Also accepts `alerts_json` (raw JSON string) and `multipart/form-data`.

**Response:**
```json
{
  "success":             true,
  "session_id":          "uuid",
  "clusters":            [...],
  "original_count":      847,
  "cluster_count":       12,
  "suppressed_count":    821,
  "review_count":        18,
  "escalate_count":      8,
  "noise_reduction_pct": 96.8
}
```

### POST /api/deduplicate

```json
{"alerts": [...], "window_seconds": 300}
```

**Response:** `{"success": true, "unique": [...], "removed": 103, "original": 206}`

---

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| TI indicator in any member | **escalate** (always, overrides similarity) |
| Critical asset + risk ≥ 65% | **escalate** |
| Rare/unknown user ≥ 65% | **escalate** |
| Off-hours ≥ 30% of members | **review** |
| Uncommon user 20–65% | **review** |
| Elevated asset risk 30–65% | **review** |
| No anomalous context | **suppressed** |

Context overrides signal similarity at every level.

---

## Context Score Dimensions

| Dimension | Description |
|-----------|-------------|
| `ti_tags` | Threat-intel indicator patterns in tags, rule.tags, threat.indicator.* |
| `has_critical_asset` | Hostname heuristic: dc-, exchange, sql, prod-, srv-, backup, etc. |
| `user_anomaly` | Users appearing in ≤ 1% of session alerts |
| `asset_risk` | Fraction of cluster members on critical assets |
| `time_anomaly` | Fraction of members outside Mon–Fri 09:00–17:00 |
| `hit_rate_anomaly` | Cluster size relative to session average |

---

## Clustering Algorithm

1. **Fingerprint** each alert by extracting the `cluster_by` fields.
2. **Group exactly** by SHA-256 hash of the fingerprint.
3. **Merge near-similar groups** where token-level Jaccard similarity ≥ threshold.
4. **Score context** per cluster across five dimensions.
5. **Assign verdict** — escalate → review → suppressed in priority order.

---

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `port` | `5009` | HTTP port |
| `db_path` | `./clusteriq.db` | SQLite database |
| `clustering.default_threshold` | `0.75` | Similarity threshold |
| `clustering.default_fields` | `[process.name, event.action, network.destination.ip]` | Default cluster-by |
| `clustering.max_alerts` | `50000` | Input cap |
| `clustering.auto_save` | `true` | Persist sessions automatically |
| `integrations.lognorm_url` | `http://127.0.0.1:5006` | LogNorm endpoint |

---

## Nebula Forge Integration

Add to `nebula-dashboard/config.yaml`:

```yaml
tools:
  clusteriq:
    label:       "ClusterIQ"
    url:         "http://127.0.0.1:5009"
    health_path: "/api/health"
    description: "Contextual alert clustering engine"
    category:    "Detection"
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.


<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

Part of the **Nebula Forge** security tools suite.

</div>
