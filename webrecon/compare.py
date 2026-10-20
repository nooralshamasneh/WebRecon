"""Compare two completed scan results (same target, different times)."""


def compare_scans(a, b):
    """a = older, b = newer (full result dicts)."""
    fa = {f["id"]: f for f in a["findings"]}
    fb = {f["id"]: f for f in b["findings"]}
    ports_a = set((a["data"].get("ports") or {}).get("open_ports", []))
    ports_b = set((b["data"].get("ports") or {}).get("open_ports", []))
    subs_a = {s["name"] for s in a["data"].get("subdomains", [])}
    subs_b = {s["name"] for s in b["data"].get("subdomains", [])}
    sa, sb = a["summary"], b["summary"]
    delta = (sb["score"] - sa["score"]) if sa["score"] is not None and sb["score"] is not None else None

    def brief(f):
        return {"id": f["id"], "title": f["title"], "severity": f["severity"]}

    return {
        "target": {"a": a["target"], "b": b["target"]},
        "grade": {"a": sa["grade"], "b": sb["grade"]},
        "score": {"a": sa["score"], "b": sb["score"], "delta": delta},
        "new_findings": [brief(fb[i]) for i in fb if i not in fa],
        "resolved_findings": [brief(fa[i]) for i in fa if i not in fb],
        "unchanged_findings": [brief(fb[i]) for i in fb if i in fa],
        "severity_changed": [{**brief(fb[i]), "from": fa[i]["severity"], "to": fb[i]["severity"]}
                             for i in fb if i in fa and fa[i]["severity"] != fb[i]["severity"]],
        "ports": {"opened": sorted(ports_b - ports_a), "closed": sorted(ports_a - ports_b)},
        "subdomains": {"added": sorted(subs_b - subs_a), "removed": sorted(subs_a - subs_b)},
    }
