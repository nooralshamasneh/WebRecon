"""TLS analysis: certificate validity/expiry/key/signature, protocol versions, weak ciphers.

Connections go to the pinned IP with the original hostname as SNI.
Protocol and cipher probing is best effort: if the local OpenSSL build cannot even offer an
old protocol or a weak cipher, that probe is reported as "untested" instead of "not supported".
"""
import socket
import ssl
import warnings
from datetime import datetime, timezone

from ..findings import make

PROTOCOLS = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
             ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]
WEAK_CIPHER_GROUPS = [("RC4", "RC4"), ("3DES", "3DES"), ("NULL", "NULL"), ("EXPORT", "EXPORT"), ("anonymous", "aNULL")]


def hostname_matches(names, host):
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _connect(ip, port, host, ctx, timeout):
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise


def _permissive_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def parse_certificate(der, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.now(timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    cn = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", key.key_size
    else:
        key_type, key_bits = type(key).__name__, None
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_remaining": (not_after - now).days, "names": san or cn, "key_type": key_type,
            "key_bits": key_bits, "signature_hash": sig, "self_signed": cert.issuer == cert.subject}


def _probe_protocol(ip, port, host, version, timeout):
    """True = accepted, False = rejected by server, None = could not be tested locally."""
    ctx = _permissive_ctx()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # probing legacy protocols is the point
            ctx.minimum_version = version
            ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError):
        return None
    try:
        with _connect(ip, port, host, ctx, timeout):
            return True
    except ssl.SSLError as exc:
        text = str(exc).upper()
        return None if "NO_PROTOCOLS_AVAILABLE" in text or "UNSUPPORTED_PROTOCOL" in text else False
    except OSError:
        return False


def _probe_cipher(ip, port, host, spec, timeout):
    ctx = _permissive_ctx()
    try:
        ctx.set_ciphers(f"{spec}:@SECLEVEL=0")
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ssl.SSLError, ValueError):
        return None  # the local OpenSSL does not ship this cipher family
    try:
        with _connect(ip, port, host, ctx, timeout):
            return True
    except (ssl.SSLError, OSError):
        return False


def analyze(ctx, host, port=443, timeout=6):
    """Return a result dict. Never raises for network errors."""
    result = {"reachable": False, "error": None, "certificate": None, "trusted": None, "verify_error": None,
              "hostname_match": None, "protocols": {}, "negotiated": None, "weak_ciphers": [], "untested": []}
    try:
        ip = ctx.pin(host)
        with _connect(ip, port, host, _permissive_ctx(), timeout) as s:
            der = s.getpeercert(binary_form=True)
            result["negotiated"] = {"version": s.version(), "cipher": (s.cipher() or [None])[0]}
        result["reachable"] = True
    except Exception as exc:  # network/TLS failure: report, do not crash the scan
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    try:
        result["certificate"] = parse_certificate(der)
        result["hostname_match"] = hostname_matches(result["certificate"]["names"], host)
    except Exception as exc:
        result["error"] = f"certificate parsing failed: {type(exc).__name__}"

    try:  # trust check against the system CA store
        with _connect(ip, port, host, ssl.create_default_context(), timeout):
            result["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        result["trusted"], result["verify_error"] = False, exc.verify_message
    except (ssl.SSLError, OSError) as exc:
        result["trusted"], result["verify_error"] = None, type(exc).__name__

    for name, version in PROTOCOLS:
        result["protocols"][name] = _probe_protocol(ip, port, host, version, timeout)
    for label, spec in WEAK_CIPHER_GROUPS:
        outcome = _probe_cipher(ip, port, host, spec, timeout)
        if outcome is None:
            result["untested"].append(label)
        elif outcome:
            result["weak_ciphers"].append(label)
    return result


def tls_findings(r):
    if not r.get("reachable"):
        return []
    out, cert = [], r.get("certificate")
    if cert:
        days = cert["days_remaining"]
        if days < 0:
            out.append(make("WR-TLS-001", [f"Expired {-days} days ago ({cert['not_after']})"]))
        elif days <= 30:
            out.append(make("WR-TLS-002", [f"Expires in {days} days ({cert['not_after']})"],
                            severity="high" if days <= 7 else "medium"))
        if cert["key_type"] == "RSA" and cert["key_bits"] and cert["key_bits"] < 2048:
            out.append(make("WR-TLS-008", [f"RSA {cert['key_bits']} bits"]))
        if cert["signature_hash"] in ("sha1", "md5"):
            out.append(make("WR-TLS-009", [f"Signature hash: {cert['signature_hash']}"]))
    if r.get("hostname_match") is False:
        out.append(make("WR-TLS-003", [f"Certificate names: {', '.join(cert['names'][:5]) or 'none'}"]))
    if r.get("trusted") is False:
        why = r.get("verify_error") or "unknown"
        out.append(make("WR-TLS-004", [why] + (["self-signed certificate"] if cert and cert["self_signed"] else [])))
    protos = r.get("protocols", {})
    old = [p for p in ("TLSv1.0", "TLSv1.1") if protos.get(p) is True]
    if old:
        out.append(make("WR-TLS-005", [f"{p} accepted" for p in old]))
    if protos.get("TLSv1.2") is False and protos.get("TLSv1.3") is False:
        out.append(make("WR-TLS-006", ["Neither TLS 1.2 nor TLS 1.3 was accepted"]))
    if r.get("weak_ciphers"):
        out.append(make("WR-TLS-007", [f"{c} ciphers accepted" for c in r["weak_ciphers"]]))
    return out
