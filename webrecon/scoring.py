"""Documented severity model: score, grade, coverage and grade caps (see docs/SCORING.md)."""
from .findings import CONFIDENCE_FACTOR, SEVERITY_WEIGHT

GRADES = ["A", "B", "C", "D", "F"]
GRADE_LABELS = {"A": "Excellent", "B": "Good", "C": "Moderate risk", "D": "Weak", "F": "Critical risk"}
COVERAGE_WEIGHTS = {"ports": 30, "http": 30, "tls": 20, "dns_mail": 20}


def points_for(finding):
    return SEVERITY_WEIGHT[finding["severity"]] * CONFIDENCE_FACTOR.get(finding.get("confidence", "confirmed"), 1.0)


def grade_for_score(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def worse(a, b):
    return a if GRADES.index(a) >= GRADES.index(b) else b


def assess(findings, modules, responded):
    """modules: {name: 'ok'|'failed'|'na'} for ports/http/tls/dns_mail. responded: did anything answer?"""
    breakdown = []
    for f in findings:
        pts = points_for(f)
        if pts:
            breakdown.append({"id": f["id"], "title": f["title"], "severity": f["severity"],
                              "confidence": f.get("confidence", "confirmed"), "points": round(pts, 1)})
    breakdown.sort(key=lambda b: -b["points"])

    applicable = {m: w for m, w in COVERAGE_WEIGHTS.items() if modules.get(m, "na") != "na"}
    done = sum(w for m, w in applicable.items() if modules.get(m) == "ok")
    coverage = round(100 * done / sum(applicable.values())) if applicable else 0
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_WEIGHT}

    if not responded:
        return {"status": "not_assessed", "grade": "N/A", "label": "Not assessed", "score": None,
                "coverage": coverage, "caps": ["The target did not respond on any scanned port or web service."],
                "counts": counts, "breakdown": breakdown}

    score = max(0, int(100 - sum(b["points"] for b in breakdown)))  # fractional points round down (conservative)
    grade = grade_for_score(score)
    caps = []

    def cap(limit, reason):
        nonlocal grade
        capped = worse(grade, limit)
        if capped != grade:  # only mention a cap when it really lowered the grade
            grade = capped
            caps.append(reason)

    confirmed = {f["severity"] for f in findings if f.get("confidence") == "confirmed"}
    if "critical" in confirmed:
        cap("D", "A confirmed critical finding caps the grade at D.")
    elif "high" in confirmed:
        cap("C", "A confirmed high-severity finding caps the grade at C.")
    if coverage < 50:
        cap("C", f"Only {coverage}% of applicable checks completed: grade capped at C.")
    elif coverage < 80:
        cap("B", f"Only {coverage}% of applicable checks completed: grade capped at B.")
    return {"status": "assessed", "grade": grade, "label": GRADE_LABELS[grade], "score": score,
            "coverage": coverage, "caps": caps, "counts": counts, "breakdown": breakdown}
