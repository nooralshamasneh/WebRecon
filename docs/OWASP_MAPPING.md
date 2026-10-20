# OWASP mapping

Generated from `webrecon/findings.py`. OWASP Top 10 edition: **2021**, ASVS version: **4.0.3**.

| ID | Finding | Default severity | OWASP Top 10 | ASVS |
|---|---|---|---|---|
| WR-HDR-001 | Missing Strict-Transport-Security (HSTS) | medium | A02:2021 Cryptographic Failures | V14.4.5, V9.1.1 |
| WR-HDR-002 | Weak HSTS configuration | low | A02:2021 Cryptographic Failures | V14.4.5 |
| WR-HDR-003 | Missing Content-Security-Policy | medium | A05:2021 Security Misconfiguration | V14.4.3 |
| WR-HDR-004 | Weak Content-Security-Policy | low | A05:2021 Security Misconfiguration | V14.4.3 |
| WR-HDR-005 | Missing clickjacking protection | medium | A05:2021 Security Misconfiguration | V14.4.7 |
| WR-HDR-006 | Missing X-Content-Type-Options | low | A05:2021 Security Misconfiguration | V14.4.4 |
| WR-HDR-007 | Missing Referrer-Policy | low | A05:2021 Security Misconfiguration | V14.4.6 |
| WR-HDR-008 | Missing Permissions-Policy | info | A05:2021 Security Misconfiguration | - |
| WR-HDR-009 | Software version disclosed in HTTP headers | low | A05:2021 Security Misconfiguration | V14.3.3 |
| WR-HDR-010 | Cookie without Secure attribute | medium | A02:2021 Cryptographic Failures | V3.4.1 |
| WR-HDR-011 | Cookie without HttpOnly attribute | low | A05:2021 Security Misconfiguration | V3.4.2 |
| WR-HDR-012 | Cookie without SameSite attribute | low | A01:2021 Broken Access Control | V3.4.3 |
| WR-HDR-013 | Permissive CORS policy | medium | A05:2021 Security Misconfiguration | V14.5.3 |
| WR-HTTP-001 | HTTPS not available | high | A02:2021 Cryptographic Failures | V9.1.1 |
| WR-HTTP-002 | HTTP does not redirect to HTTPS | medium | A02:2021 Cryptographic Failures | V9.1.1 |
| WR-TLS-001 | TLS certificate expired | high | A02:2021 Cryptographic Failures | V9.2.1 |
| WR-TLS-002 | TLS certificate expires soon | medium | A02:2021 Cryptographic Failures | V9.2.1 |
| WR-TLS-003 | Certificate does not match the hostname | high | A02:2021 Cryptographic Failures | V9.2.1 |
| WR-TLS-004 | Certificate chain not trusted | high | A02:2021 Cryptographic Failures | V9.2.1 |
| WR-TLS-005 | Deprecated TLS protocol enabled (TLS 1.0 / 1.1) | medium | A02:2021 Cryptographic Failures | V9.1.2, V9.1.3 |
| WR-TLS-006 | TLS 1.2 or higher not supported | high | A02:2021 Cryptographic Failures | V9.1.2 |
| WR-TLS-007 | Weak cipher suite accepted | high | A02:2021 Cryptographic Failures | V9.1.2 |
| WR-TLS-008 | Weak certificate key size | medium | A02:2021 Cryptographic Failures | V6.2.3 |
| WR-TLS-009 | Weak certificate signature algorithm | medium | A02:2021 Cryptographic Failures | V6.2.5 |
| WR-PATH-001 | Git repository exposed | critical | A05:2021 Security Misconfiguration | V14.3.2, V4.3.2 |
| WR-PATH-002 | Environment file exposed | critical | A05:2021 Security Misconfiguration | V14.3.2, V2.10.4 |
| WR-PATH-003 | Administrative interface reachable | medium | A01:2021 Broken Access Control | V4.3.1 |
| WR-PATH-004 | Debug or status page exposed | high | A05:2021 Security Misconfiguration | V14.3.2 |
| WR-PATH-005 | Metadata file exposed (.DS_Store) | low | A05:2021 Security Misconfiguration | V14.3.2 |
| WR-PORT-001 | Telnet exposed | high | A02:2021 Cryptographic Failures | V9.1.1 |
| WR-PORT-002 | FTP exposed | medium | A02:2021 Cryptographic Failures | V9.1.1 |
| WR-PORT-003 | Windows remote services exposed (SMB / RDP) | high | A05:2021 Security Misconfiguration | V1.14.4 |
| WR-PORT-004 | Database or cache service exposed | high | A05:2021 Security Misconfiguration | V1.14.4 |
| WR-PORT-005 | Clear-text mail protocol offered | low | A02:2021 Cryptographic Failures | V9.1.1 |
| WR-VULN-001 | Known vulnerabilities for detected software version | medium | A06:2021 Vulnerable and Outdated Components | V14.2.1 |
| WR-MAIL-001 | No SPF record | medium | A05:2021 Security Misconfiguration | - |
| WR-MAIL-002 | SPF allows any sender | high | A05:2021 Security Misconfiguration | - |
| WR-MAIL-003 | SPF uses soft-fail (~all) | low | A05:2021 Security Misconfiguration | - |
| WR-MAIL-004 | SPF exceeds the 10 DNS lookup limit | medium | A05:2021 Security Misconfiguration | - |
| WR-MAIL-005 | Multiple SPF records | medium | A05:2021 Security Misconfiguration | - |
| WR-MAIL-006 | No DMARC record | medium | A05:2021 Security Misconfiguration | - |
| WR-MAIL-007 | DMARC policy is p=none | low | A05:2021 Security Misconfiguration | - |
| WR-MAIL-008 | DMARC has no aggregate report address (rua) | info | A09:2021 Security Logging and Monitoring Failures | - |
| WR-MAIL-009 | No DKIM key found for common selectors | info | A05:2021 Security Misconfiguration | - |
| WR-DNS-001 | Subdomain resolves to a private address | low | A05:2021 Security Misconfiguration | - |
| WR-DNS-002 | Domain registration expires soon | medium | A05:2021 Security Misconfiguration | - |

Secure header guidance: <https://owasp.org/www-project-secure-headers/>
ASVS: <https://owasp.org/www-project-application-security-verification-standard/>

