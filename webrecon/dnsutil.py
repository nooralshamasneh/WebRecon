"""Thin dnspython wrapper (lazy import so the rest of the app works without it)."""


def lookup(name, rtype, lifetime=5):
    """Return a list of record strings, or [] when nothing is found."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:  # pragma: no cover
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(3, lifetime)
    try:
        answers = resolver.resolve(name, rtype)
    except dns.exception.DNSException:
        return []
    out = []
    for rdata in answers:
        if rtype == "TXT":
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        else:
            out.append(str(rdata).rstrip("."))
    return out


def txt_records(name):
    return lookup(name, "TXT")
