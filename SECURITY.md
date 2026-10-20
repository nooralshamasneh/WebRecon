# Security Policy

## Responsible use

WebRecon performs active reconnaissance (port scanning, service detection, HTTP probing, DNS brute forcing).
**Only scan systems you own or have explicit written permission to test.** Unauthorized scanning may be illegal.
The software is provided without warranty (see [LICENSE](LICENSE)).

WebRecon enforces this technically: a scan of an arbitrary target requires **proof of ownership** (DNS TXT record
or a token file). `scanme.nmap.org` (which explicitly permits scanning) is allowed for practice.

## Security design

| Area                | Control                                                                                                                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Input               | Strict parser: domain, IP or http(s) host only; rejects ports, credentials, decimal/hex/octal IPs, shell metacharacters                                                                    |
| SSRF                | Every hostname is resolved once per scan and **pinned**; non-public, mixed and reserved addresses are refused; every redirect hop is re-validated; proxy environment variables are ignored |
| Command execution   | nmap runs with an argument list (no shell), on the pinned IP, after `--`                                                                                                                   |
| Authentication      | Scrypt/PBKDF2 password hashes (Werkzeug), 12+ character passwords, session cookies (`HttpOnly`, `SameSite=Lax`, optional `Secure`), hashed API tokens                                      |
| CSRF                | Per-session token on every state-changing browser request; bearer-token API calls are exempt                                                                                               |
| Brute force / abuse | Login lockout per IP+user, per-user scan quota, pending-scan cap, API rate limit                                                                                                           |
| Auditability        | Append-only `audit_log` table (logins, scans, denials, token changes); control characters stripped from log details                                                                        |
| Output              | Jinja2 autoescaping, ReportLab text escaped, strict CSP (no inline script/style), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`                                       |
| Container           | Non-root user, data volume only, health check                                                                                                                                              |

## Known limitations

- The rate limiter and queue workers are per process: run a single process (the Docker image does).
- Add TLS in front (reverse proxy) before exposing WebRecon beyond localhost, and set `WEBRECON_HTTPS=1`.
- Third-party passive sources (crt.sh, CertSpotter, HackerTarget, AlienVault OTX, Anubis) and NVD receive the
  scanned **domain name or software CPE**, never scan results. Disable with `WEBRECON_PASSIVE_SOURCES=0` / `WEBRECON_NVD=0`.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting (Security tab > "Report a vulnerability") instead of a public issue.
Include steps to reproduce and the affected version. You will get an answer within a few days.
