"""Finding catalogue: every check WebRecon can report, mapped to OWASP Top 10 and ASVS.

Mapping versions are constants so they can be updated in one place.
Generate docs with:  python -m webrecon.findings > docs/OWASP_MAPPING.md
"""
OWASP_TOP10_VERSION = "2025"
ASVS_VERSION = "4.0.3"

OWASP_TOP10 = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging & Alerting Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
}
_TOP10 = "https://top10.owasp.org/2025/"
TOP10_URLS = {
    "A01": _TOP10 + "A01_2025-Broken_Access_Control/",
    "A02": _TOP10 + "A02_2025-Security_Misconfiguration/",
    "A03": _TOP10 + "A03_2025-Software_Supply_Chain_Failures/",
    "A04": _TOP10 + "A04_2025-Cryptographic_Failures/",
    "A05": _TOP10 + "A05_2025-Injection/",
    "A06": _TOP10 + "A06_2025-Insecure_Design/",
    "A07": _TOP10 + "A07_2025-Authentication_Failures/",
    "A08": _TOP10 + "A08_2025-Software_or_Data_Integrity_Failures/",
    "A09": _TOP10 + "A09_2025-Security_Logging_and_Alerting_Failures/",
    "A10": _TOP10 + "A10_2025-Mishandling_of_Exceptional_Conditions/",
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
CONFIDENCE_FACTOR = {"confirmed": 1.0, "tentative": 0.5}

SH = "https://owasp.org/www-project-secure-headers/"
CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
REF_HSTS = CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"
REF_CSP = CS + "Content_Security_Policy_Cheat_Sheet.html"
REF_CLICK = CS + "Clickjacking_Defense_Cheat_Sheet.html"
REF_TLS = CS + "Transport_Layer_Security_Cheat_Sheet.html"
REF_SESS = CS + "Session_Management_Cheat_Sheet.html"
REF_CORS = CS + "HTML5_Security_Cheat_Sheet.html"
REF_SPF = "https://datatracker.ietf.org/doc/html/rfc7208"
REF_DMARC = "https://datatracker.ietf.org/doc/html/rfc7489"

CATALOG = {}


def _f(fid, title, severity, owasp, asvs, description, remediation, refs=()):
    CATALOG[fid] = {"id": fid, "title": title, "severity": severity, "owasp": owasp, "asvs": list(asvs),
                    "description": description, "remediation": remediation, "references": list(refs)}


# ---- HTTP security headers / cookies / CORS --------------------------------------------------
_f("WR-HDR-001", "Missing Strict-Transport-Security (HSTS)", "medium", "A04", ["V14.4.5", "V9.1.1"],
   "Browsers are not told to use HTTPS only, which leaves users open to protocol-downgrade and SSL-stripping attacks.",
   "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains", [SH, REF_HSTS])
_f("WR-HDR-002", "Weak HSTS configuration", "low", "A04", ["V14.4.5"],
   "HSTS is present but max-age is shorter than 6 months.",
   "Use max-age of at least 15552000 (preferably 31536000) and includeSubDomains.", [REF_HSTS])
_f("WR-HDR-003", "Missing Content-Security-Policy", "medium", "A02", ["V14.4.3"],
   "No CSP is sent, so injected scripts are not restricted by the browser.",
   "Start with: Content-Security-Policy: default-src 'self'; frame-ancestors 'self' (test before enforcing).",
   [SH, REF_CSP])
_f("WR-HDR-004", "Weak Content-Security-Policy", "low", "A02", ["V14.4.3"],
   "The CSP allows 'unsafe-inline', 'unsafe-eval' or wildcard sources, which weakens XSS protection.",
   "Remove unsafe-inline/unsafe-eval (use nonces or hashes) and avoid wildcard sources.", [REF_CSP])
_f("WR-HDR-005", "Missing clickjacking protection", "medium", "A02", ["V14.4.7"],
   "Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be framed by other origins.",
   "Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.", [SH, REF_CLICK])
_f("WR-HDR-006", "Missing X-Content-Type-Options", "low", "A02", ["V14.4.4"],
   "Browsers may MIME-sniff responses and execute content with an unexpected type.",
   "Send: X-Content-Type-Options: nosniff", [SH])
_f("WR-HDR-007", "Missing Referrer-Policy", "low", "A02", ["V14.4.6"],
   "Full URLs (possibly containing tokens or identifiers) may leak to third-party sites through the Referer header.",
   "Send: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).", [SH])
_f("WR-HDR-008", "Missing Permissions-Policy", "info", "A02", [],
   "Powerful browser features (camera, geolocation, ...) are not explicitly restricted.",
   "Send a Permissions-Policy header that disables unused features, e.g. camera=(), geolocation=().", [SH])
_f("WR-HDR-009", "Software version disclosed in HTTP headers", "low", "A02", ["V14.3.3"],
   "Server or X-Powered-By reveals product and version, which helps attackers choose known exploits.",
   "Remove or genericise the Server and X-Powered-By headers (e.g. server_tokens off; expose_php=Off).", [SH])
_f("WR-HDR-010", "Cookie without Secure attribute", "medium", "A04", ["V3.4.1"],
   "A cookie can be sent over plain HTTP and intercepted.", "Set the Secure attribute on all cookies.", [REF_SESS])
_f("WR-HDR-011", "Cookie without HttpOnly attribute", "low", "A02", ["V3.4.2"],
   "JavaScript can read the cookie, so an XSS bug can steal it.", "Set HttpOnly on session cookies.", [REF_SESS])
_f("WR-HDR-012", "Cookie without SameSite attribute", "low", "A01", ["V3.4.3"],
   "Without SameSite the browser's default applies, which varies and may allow cross-site requests.",
   "Set SameSite=Lax (or Strict) on session cookies.", [REF_SESS])
_f("WR-HDR-013", "Permissive CORS policy", "medium", "A02", ["V14.5.3"],
   "The server reflects arbitrary origins or uses a wildcard, optionally with credentials.",
   "Allow only an explicit list of trusted origins and never combine wildcard origins with credentials.", [REF_CORS])

# ---- Transport ----------------------------------------------------------------------------------
_f("WR-HTTP-001", "HTTPS not available", "high", "A04", ["V9.1.1"],
   "The site only answers over plain HTTP, so all traffic is readable and modifiable on the network.",
   "Install a certificate (e.g. Let's Encrypt) and serve the site over HTTPS.", [REF_TLS])
_f("WR-HTTP-002", "HTTP does not redirect to HTTPS", "medium", "A04", ["V9.1.1"],
   "Plain-HTTP requests are served instead of being redirected to HTTPS.",
   "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.", [REF_HSTS])
_f("WR-TLS-001", "TLS certificate expired", "high", "A04", ["V9.2.1"],
   "Browsers show a security error and clients cannot trust the server identity.", "Renew the certificate.", [REF_TLS])
_f("WR-TLS-002", "TLS certificate expires soon", "medium", "A04", ["V9.2.1"],
   "The certificate will expire shortly, causing an outage and browser warnings.",
   "Renew now and automate renewal (ACME).", [REF_TLS])
_f("WR-TLS-003", "Certificate does not match the hostname", "high", "A04", ["V9.2.1"],
   "The certificate's names do not include the scanned hostname.",
   "Issue a certificate that includes this hostname in its SAN list.", [REF_TLS])
_f("WR-TLS-004", "Certificate chain not trusted", "high", "A04", ["V9.2.1"],
   "The certificate is self-signed or issued by an unknown or incomplete chain.",
   "Use a certificate from a public CA and serve the full intermediate chain.", [REF_TLS])
_f("WR-TLS-005", "Deprecated TLS protocol enabled (TLS 1.0 / 1.1)", "medium", "A04", ["V9.1.2", "V9.1.3"],
   "TLS 1.0 and 1.1 are deprecated and vulnerable to known downgrade and padding attacks.",
   "Disable TLS 1.0 and 1.1; support TLS 1.2 and TLS 1.3 only.", [REF_TLS])
_f("WR-TLS-006", "TLS 1.2 or higher not supported", "high", "A04", ["V9.1.2"],
   "The server does not negotiate a modern TLS version.", "Enable TLS 1.2 and TLS 1.3.", [REF_TLS])
_f("WR-TLS-007", "Weak cipher suite accepted", "high", "A04", ["V9.1.2"],
   "The server accepts a broken or weak cipher family (RC4, 3DES, NULL, EXPORT, anonymous).",
   "Restrict ciphers to modern AEAD suites (AES-GCM, ChaCha20-Poly1305).", [REF_TLS])
_f("WR-TLS-008", "Weak certificate key size", "medium", "A04", ["V6.2.3"],
   "The certificate public key is shorter than recommended (RSA < 2048 bits).",
   "Re-issue the certificate with RSA 2048+ or an ECDSA P-256 key.", [REF_TLS])
_f("WR-TLS-009", "Weak certificate signature algorithm", "medium", "A04", ["V6.2.5"],
   "The certificate is signed with SHA-1 or MD5.", "Re-issue the certificate with SHA-256 or stronger.", [REF_TLS])

# ---- Exposed content ---------------------------------------------------------------------------
_f("WR-PATH-001", "Git repository exposed", "critical", "A02", ["V14.3.2", "V4.3.2"],
   "/.git/ is downloadable, which can disclose the full source code, history and secrets.",
   "Block access to dot-directories at the web server and remove .git from the document root.")
_f("WR-PATH-002", "Environment file exposed", "critical", "A02", ["V14.3.2", "V2.10.4"],
   "A .env file is publicly readable and usually contains credentials and API keys.",
   "Remove the file from the web root, block dotfiles, and rotate every exposed secret.")
_f("WR-PATH-003", "Administrative interface reachable", "medium", "A01", ["V4.3.1"],
   "An admin path answers publicly. It may be protected, but it enlarges the attack surface.",
   "Restrict by IP/VPN, require MFA, and do not expose admin panels to the internet.")
_f("WR-PATH-004", "Debug or status page exposed", "high", "A02", ["V14.3.2"],
   "A diagnostic page (phpinfo, server-status, framework actuator) reveals configuration details.",
   "Disable debug endpoints in production or restrict them to trusted networks.")
_f("WR-PATH-005", "Metadata file exposed (.DS_Store)", "low", "A02", ["V14.3.2"],
   "A .DS_Store file lists directory contents of the deployment machine.", "Delete it and block dotfiles.")

# ---- Network services ----------------------------------------------------------------------------
_f("WR-PORT-001", "Telnet exposed", "high", "A04", ["V9.1.1"],
   "Telnet sends credentials and data in clear text.", "Disable Telnet and use SSH.")
_f("WR-PORT-002", "FTP exposed", "medium", "A04", ["V9.1.1"],
   "Plain FTP sends credentials in clear text (FTPS/SFTP are safer).", "Replace with SFTP or enforce FTPS and restrict access.")
_f("WR-PORT-003", "Windows remote services exposed (SMB / RDP)", "high", "A02", ["V1.14.4"],
   "SMB and RDP are common ransomware and brute-force targets and should not face the internet.",
   "Close the ports at the firewall; use a VPN or gateway.")
_f("WR-PORT-004", "Database or cache service exposed", "high", "A02", ["V1.14.4"],
   "A database, cache or search service accepts connections from the internet.",
   "Bind to localhost/private networks and require authentication and TLS.")
_f("WR-PORT-005", "Clear-text mail protocol offered", "low", "A04", ["V9.1.1"],
   "POP3/IMAP on the plain ports can expose credentials unless STARTTLS is enforced.",
   "Use POP3S/IMAPS (995/993) or require STARTTLS, and disable plain login.")
_f("WR-VULN-001", "Known vulnerabilities for detected software version", "medium", "A03", ["V14.2.1"],
   "NVD lists CVEs affecting the detected product/version. Matching is version-based, so distributions that "
   "back-port fixes (Debian/Ubuntu/RHEL) can produce false positives.",
   "Verify the exact package version, apply vendor updates, and remove unused software.",
   ["https://nvd.nist.gov/"])

# ---- Email authentication / DNS ------------------------------------------------------------------
_f("WR-MAIL-001", "No SPF record", "medium", "A02", [],
   "Without SPF anyone can send mail that appears to come from this domain.",
   "Publish an SPF record, e.g. v=spf1 include:<provider> -all (or v=spf1 -all if the domain sends no mail).", [REF_SPF])
_f("WR-MAIL-002", "SPF allows any sender", "high", "A02", [],
   "The SPF record ends with +all or ?all, which authorises or ignores every sender.",
   "End the record with -all (or ~all while testing).", [REF_SPF])
_f("WR-MAIL-003", "SPF uses soft-fail (~all)", "low", "A02", [],
   "Unauthorised mail is only marked suspicious.", "Move to -all once all legitimate senders are listed.", [REF_SPF])
_f("WR-MAIL-004", "SPF exceeds the 10 DNS lookup limit", "medium", "A02", [],
   "More than 10 lookups cause a PermError, so receivers may ignore the policy.",
   "Flatten includes and remove unused mechanisms.", [REF_SPF])
_f("WR-MAIL-005", "Multiple SPF records", "medium", "A02", [],
   "More than one v=spf1 record causes a PermError.", "Merge all SPF data into a single record.", [REF_SPF])
_f("WR-MAIL-006", "No DMARC record", "medium", "A02", [],
   "Receivers have no policy for spoofed mail and you get no reports.",
   "Publish _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain", [REF_DMARC])
_f("WR-MAIL-007", "DMARC policy is p=none", "low", "A02", [],
   "DMARC only monitors; spoofed mail is still delivered.", "Move to p=quarantine and then p=reject.", [REF_DMARC])
_f("WR-MAIL-008", "DMARC has no aggregate report address (rua)", "info", "A09", [],
   "Without rua you cannot see who sends mail as your domain.", "Add rua=mailto:... to the DMARC record.", [REF_DMARC])
_f("WR-MAIL-009", "No DKIM key found for common selectors", "info", "A02", [],
   "No DKIM record was found for the common selectors tested. This is inconclusive: selectors are arbitrary names.",
   "Make sure outgoing mail is DKIM-signed and publish the selector record.")
_f("WR-DNS-001", "Subdomain resolves to a private address", "low", "A02", [],
   "A public DNS name points to a private (RFC 1918 / loopback) address, leaking internal network layout.",
   "Remove internal records from public DNS or use split-horizon DNS.")
_f("WR-DNS-002", "Domain registration expires soon", "medium", "A02", [],
   "An expired domain can be hijacked or taken offline.", "Renew the domain and enable auto-renew.")


def make(fid, evidence=None, severity=None, confidence="confirmed", description=None):
    """Create a finding dict from the catalogue (optionally overriding severity/evidence)."""
    base = CATALOG[fid]
    finding = {k: (list(v) if isinstance(v, list) else v) for k, v in base.items()}
    finding["owasp_name"] = OWASP_TOP10.get(base["owasp"], base["owasp"])
    if severity:
        finding["severity"] = severity
    if description:
        finding["description"] = description
    finding["confidence"] = confidence
    finding["evidence"] = [str(e) for e in (evidence or [])]
    return finding


def to_markdown():
    lines = ["# OWASP mapping", "",
             f"Generated from `webrecon/findings.py`. OWASP Top 10 edition: **{OWASP_TOP10_VERSION}**, "
             f"ASVS version: **{ASVS_VERSION}**.", "",
             "| ID | Finding | Default severity | OWASP Top 10 | ASVS |", "|---|---|---|---|---|"]
    for f in CATALOG.values():
        asvs = ", ".join(f["asvs"]) or "-"
        lines.append(f"| {f['id']} | {f['title']} | {f['severity']} | {OWASP_TOP10[f['owasp']]} | {asvs} |")
    lines += ["", "Secure header guidance: <https://owasp.org/www-project-secure-headers/>",
              "ASVS: <https://owasp.org/www-project-application-security-verification-standard/>"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(to_markdown())
