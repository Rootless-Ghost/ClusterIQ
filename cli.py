#!/usr/bin/env python3
"""
ClusterIQ CLI
Cluster and analyze alerts from the command line.

Usage:
    python cli.py --alerts alerts.json
    python cli.py --alerts alerts.json --fields process.name,event.action --threshold 0.8
    python cli.py --alerts alerts.json --output session.md
    python cli.py --dedup --alerts alerts.json --window 300
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


def _load_alerts(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        raw = fh.read().strip()
    if raw.startswith("["):
        data = json.loads(raw)
        return [e for e in data if isinstance(e, dict)]
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


def _print_summary(session: dict) -> None:
    print(f"\n{'='*60}")
    print(f"  ClusterIQ Session: {session.get('label', '')}")
    print(f"{'='*60}")
    print(f"  Original alerts:  {session.get('original_count', 0):,}")
    print(f"  Clusters:         {session.get('cluster_count', 0)}")
    print(f"  Suppressed:       {session.get('suppressed_count', 0):,}")
    print(f"  Review:           {session.get('review_count', 0):,}")
    print(f"  Escalate:         {session.get('escalate_count', 0):,}")
    print(f"  Noise reduction:  {session.get('noise_reduction_pct', 0):.1f}%")
    print(f"  Threshold:        {session.get('similarity_threshold', 0.75):.2f}")
    fields = ", ".join(session.get("cluster_by", []))
    print(f"  Cluster by:       {fields}")
    print()


def cmd_cluster(args: argparse.Namespace, engine) -> None:
    alerts     = _load_alerts(args.alerts)
    cluster_by = [f.strip() for f in args.fields.split(",")] if args.fields else None
    threshold  = args.threshold
    label      = args.label or f"CLI session — {len(alerts)} alerts"
    save       = not args.no_save

    print(f"[+] Loaded {len(alerts)} alert(s)")
    print(f"[+] Clustering (threshold={threshold}, fields={cluster_by or 'default'})…")

    session = engine.cluster(
        alerts=alerts,
        cluster_by=cluster_by,
        similarity_threshold=threshold,
        label=label,
        save=save,
    )

    _print_summary(session)

    # Per-verdict breakdown
    for vkey, symbol, label_str in [
        ("escalate",   "!", "ESCALATE"),
        ("review",     "?", "REVIEW"),
        ("suppressed", "-", "SUPPRESSED"),
    ]:
        clusters = [c for c in session.get("clusters", []) if c.get("noise_verdict") == vkey]
        if not clusters:
            continue
        print(f"  [{symbol}] {label_str} ({len(clusters)} clusters):")
        for c in clusters[:20]:
            fp_str = " | ".join(f"{k}={v}" for k, v in (c.get("fingerprint") or {}).items())
            ctx    = c.get("context_scores", {})
            ti_tag = " [TI]" if ctx.get("ti_tags") else ""
            ca_tag = " [CRIT]" if ctx.get("has_critical_asset") else ""
            print(f"      {c['cluster_id']:<4} size={c['size']:<5} sim={c['similarity_score']:.2f}  "
                  f"{fp_str[:50]}{ti_tag}{ca_tag}")
        if len(clusters) > 20:
            print(f"      … and {len(clusters) - 20} more")
        print()

    # Output file
    if args.output:
        fmt = "markdown" if args.output.endswith(".md") else "json"
        if fmt == "markdown":
            content = engine.to_markdown(session)
        else:
            content = json.dumps(session, indent=2, ensure_ascii=False)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"[+] Session saved to: {args.output}")
    elif args.format == "json":
        print(json.dumps(session, indent=2, ensure_ascii=False))


def cmd_dedup(args: argparse.Namespace, engine) -> None:
    alerts = _load_alerts(args.alerts)
    print(f"[+] Loaded {len(alerts)} alert(s)")
    print(f"[+] Deduplicating (window={args.window}s)…")

    result = engine.deduplicate(alerts, window_seconds=args.window)
    print(f"\n  Original:  {result['original']:,}")
    print(f"  Unique:    {len(result['unique']):,}")
    print(f"  Removed:   {result['removed']:,}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result["unique"], fh, indent=2, ensure_ascii=False)
        print(f"\n[+] Unique alerts saved to: {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="clusteriq",
        description="ClusterIQ — Contextual Alert Clustering Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --alerts alerts.json
  %(prog)s --alerts alerts.json --fields process.name,event.action --threshold 0.8
  %(prog)s --alerts alerts.json --output session.md
  %(prog)s --dedup --alerts alerts.json --window 300
        """,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cluster", action="store_true", default=True,
                      help="Cluster alerts (default)")
    mode.add_argument("--dedup",   action="store_true",
                      help="Deduplicate alerts within a time window")

    parser.add_argument("--alerts",    "-a", metavar="FILE",
                        required=True, help="ECS-lite alerts JSON file")
    parser.add_argument("--fields",    "-f", metavar="FIELDS",
                        help="Comma-separated cluster-by fields")
    parser.add_argument("--threshold", "-t", type=float, default=0.75,
                        help="Similarity threshold 0.0–1.0 (default: 0.75)")
    parser.add_argument("--window",    "-w", type=int,   default=300,
                        help="Dedup time window in seconds (default: 300)")
    parser.add_argument("--label",     "-l", metavar="LABEL",
                        help="Human-readable session label")
    parser.add_argument("--format",         default="summary",
                        choices=["summary", "json"],
                        help="Output format (default: summary)")
    parser.add_argument("--output",    "-o", metavar="FILE",
                        help="Save output to file (.md or .json)")
    parser.add_argument("--no-save",   action="store_true",
                        help="Do not persist session to database")
    parser.add_argument("--config",          default="config.yaml",
                        help="Path to config.yaml")

    args = parser.parse_args()

    config = {"db_path": "./clusteriq.db", "clustering": {"default_threshold": 0.75}}
    if os.path.exists(args.config):
        try:
            import yaml
            with open(args.config, encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            config.update(loaded)
        except Exception:
            pass

    from core.engine import ClusterEngine
    engine = ClusterEngine(config)

    if args.dedup:
        cmd_dedup(args, engine)
    else:
        cmd_cluster(args, engine)


if __name__ == "__main__":
    main()
