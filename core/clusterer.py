"""
ClusterIQ — Alert clustering algorithm.

Algorithm:
  1. Build fingerprint dicts for all alerts from the cluster_by fields.
  2. Group alerts by exact fingerprint hash (O(n)).
  3. Attempt to merge near-similar exact groups above similarity_threshold
     (O(g²) on unique group count, which is typically far smaller than n).
  4. Sort clusters by size descending, reassign sequential IDs.
"""

import logging
from .fingerprint import build_fingerprint, fingerprint_hash, similarity_score

logger = logging.getLogger("clusteriq.clusterer")

# Fields checked when no cluster_by is supplied
DEFAULT_CLUSTER_BY: list[str] = [
    "process.name",
    "event.action",
    "network.destination.ip",
]


def cluster_alerts(
    alerts:               list[dict],
    cluster_by:           list[str],
    similarity_threshold: float = 0.75,
) -> list[dict]:
    """
    Group alerts into fingerprint-based clusters.

    Returns a list of cluster dicts (unsorted by verdict, sorted by size):
    {
      "cluster_id":       str,
      "fingerprint":      dict,    # representative field→value mapping
      "fp_hash":          str,     # hash of representative fingerprint
      "size":             int,
      "representative":   dict,    # a single member alert used as the example
      "similarity_score": float,   # average intra-cluster similarity (0–1)
      "members":          list[dict],
    }
    """
    if not alerts:
        return []

    effective_fields = cluster_by if cluster_by else DEFAULT_CLUSTER_BY
    logger.debug(
        "Clustering %d alerts by fields=%s threshold=%.2f",
        len(alerts), effective_fields, similarity_threshold,
    )

    # Step 1 — build fingerprints
    items = []
    for alert in alerts:
        fp = build_fingerprint(alert, effective_fields)
        h  = fingerprint_hash(fp)
        items.append({"alert": alert, "fp": fp, "hash": h})

    # Step 2 — group by exact hash
    groups: dict[str, list] = {}
    for item in items:
        groups.setdefault(item["hash"], []).append(item)

    # Step 3 — merge near-similar groups
    group_keys    = list(groups.keys())
    merged_into: dict[str, str] = {}  # child_hash → parent_hash

    for i, h1 in enumerate(group_keys):
        if h1 in merged_into:
            continue
        fp1 = groups[h1][0]["fp"]

        for j in range(i + 1, len(group_keys)):
            h2 = group_keys[j]
            if h2 in merged_into:
                continue
            fp2 = groups[h2][0]["fp"]

            sim = similarity_score(fp1, fp2)
            if sim >= similarity_threshold and sim < 1.0:
                # Absorb h2 into h1
                groups[h1].extend(groups[h2])
                merged_into[h2] = h1

    # Step 4 — build cluster dicts
    clusters: list[dict] = []
    for h, group_items in groups.items():
        if h in merged_into:
            continue   # skip absorbed groups

        members  = [it["alert"] for it in group_items]
        rep_fp   = group_items[0]["fp"]

        # Average similarity of a sample (max 20 pairs) to avoid O(n²) on large groups
        sample   = group_items[:10]
        sim_vals = []
        for a in range(len(sample)):
            for b in range(a + 1, len(sample)):
                sim_vals.append(similarity_score(sample[a]["fp"], sample[b]["fp"]))
        avg_sim = round(sum(sim_vals) / len(sim_vals), 4) if sim_vals else 1.0

        clusters.append({
            "cluster_id":       "",     # assigned after sort
            "fingerprint":      rep_fp,
            "fp_hash":          h,
            "size":             len(members),
            "representative":   members[0],
            "similarity_score": avg_sim,
            "members":          members,
        })

    # Sort by size descending, then assign sequential IDs
    clusters.sort(key=lambda c: c["size"], reverse=True)
    for idx, cl in enumerate(clusters, 1):
        cl["cluster_id"] = f"c{idx}"

    logger.debug("Produced %d clusters", len(clusters))
    return clusters
