"""SPF / DKIM / DMARC analysis from DNS."""
import re

from .. import dnsutil
from ..findings import make

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "mandrill"]
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")


def parse_spf(record):
    tokens = record.split()[1:]
    all_q, lookups, includes = None, 0, []
    for tok in tokens:
        t = tok.lower()
        m = re.fullmatch(r"([+\-~?]?)all", t)
        if m:
            all_q = m.group(1) or "+"
            continue
        name = re.split(r"[:=/]", t.lstrip("+-~?"), maxsplit=1)[0]
        if name in LOOKUP_MECHANISMS:
            lookups += 1
            if name in ("include", "redirect") and (":" in t or "=" in t):
                includes.append(re.split(r"[:=]", t, maxsplit=1)[1])
    return {"all": all_q, "lookups": lookups, "includes": includes}


def count_spf_lookups(record, txt_lookup, depth=0, seen=None, budget=None):
    """Total DNS-lookup mechanisms including nested includes (capped, to bound DNS queries)."""
    seen = seen if seen is not None else set()
    budget = budget if budget is not None else [30]
    parsed = parse_spf(record)
    total = parsed["lookups"]
    if depth >= 10:
        return total
    for inc in parsed["includes"]:
        if inc in seen or budget[0] <= 0:
            continue
        seen.add(inc)
        budget[0] -= 1
        for txt in txt_lookup(inc):
            if txt.lower().startswith("v=spf1"):
                total += count_spf_lookups(txt, txt_lookup, depth + 1, seen, budget)
                break
    return total


def parse_dmarc(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze(domain):
    txt = dnsutil.txt_records
    has_mx = bool(dnsutil.lookup(domain, "MX"))
    spf_records = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
    dmarc_records = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    selectors = [s for s in DKIM_SELECTORS
                 if any(r for r in dnsutil.lookup(f"{s}._domainkey.{domain}", "TXT")
                        + dnsutil.lookup(f"{s}._domainkey.{domain}", "CNAME"))]
    findings, info = [], {"has_mx": has_mx, "spf": None, "dmarc": None, "dkim_selectors": selectors}
    sev_missing = "medium" if has_mx else "low"

    if not spf_records:
        findings.append(make("WR-MAIL-001", [] if has_mx else ["Domain has no MX record: publish v=spf1 -all"],
                             severity=sev_missing))
    else:
        if len(spf_records) > 1:
            findings.append(make("WR-MAIL-005", spf_records))
        spf = spf_records[0]
        parsed = parse_spf(spf)
        parsed["total_lookups"] = count_spf_lookups(spf, txt)
        parsed["record"] = spf
        info["spf"] = parsed
        if parsed["all"] in ("+", "?"):
            findings.append(make("WR-MAIL-002", [spf]))
        elif parsed["all"] == "~":
            findings.append(make("WR-MAIL-003", [spf]))
        elif parsed["all"] is None and "redirect=" not in spf.lower():
            findings.append(make("WR-MAIL-002", ["No 'all' mechanism: " + spf], severity="medium"))
        if parsed["total_lookups"] > 10:
            findings.append(make("WR-MAIL-004", [f"{parsed['total_lookups']} DNS lookups"]))

    if not dmarc_records:
        findings.append(make("WR-MAIL-006", [], severity=sev_missing))
    else:
        tags = parse_dmarc(dmarc_records[0])
        info["dmarc"] = {"record": dmarc_records[0], **tags}
        if tags.get("p", "none").lower() == "none":
            findings.append(make("WR-MAIL-007", [dmarc_records[0]]))
        if "rua" not in tags:
            findings.append(make("WR-MAIL-008"))

    if has_mx and not selectors:
        findings.append(make("WR-MAIL-009", [f"Selectors tried: {', '.join(DKIM_SELECTORS)}"]))
    return {"info": info, "findings": findings}
