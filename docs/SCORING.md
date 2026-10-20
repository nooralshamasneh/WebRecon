# Severity and scoring model

Every finding comes from the catalogue in `webrecon/findings.py` and has a severity, an OWASP Top 10 category,
ASVS references, a remediation, and a confidence level. The model is implemented in `webrecon/scoring.py`.

## Severity

| Severity | Meaning                                                                                                                                           | Points |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| critical | Directly exploitable exposure (e.g. `.git` or `.env` readable)                                                                                    | 30     |
| high     | Serious weakness that is easy to abuse (untrusted/mismatched certificate, exposed SMB/RDP/database, permissive CORS with credentials, SPF `+all`) | 15     |
| medium   | Missing protection with real impact (no CSP, no HSTS, no DMARC, Secure flag missing)                                                              | 7      |
| low      | Hardening gap or information leak                                                                                                                 | 2      |
| info     | Advisory only                                                                                                                                     | 0      |

Confidence: **confirmed** findings count in full; **tentative** findings (version-based CVE matches, which can be false positives
because Linux distributions back-port fixes) count **half**.

## Score and grade

`score = 100 - sum(points)`, floored at 0, fractions rounded down. Each finding id counts once.

| Score  | Grade           |
| ------ | --------------- |
| 90-100 | A Excellent     |
| 80-89  | B Good          |
| 70-79  | C Moderate risk |
| 50-69  | D Weak          |
| 0-49   | F Critical risk |

## Caps (a good number cannot hide a serious problem)

- A confirmed **critical** finding caps the grade at **D**; a confirmed **high** finding caps it at **C**.
- **Coverage** is the share of applicable checks that completed (ports 30, HTTP 30, TLS 20, DNS/e-mail 20 weight points;
  a check that does not apply, e.g. TLS on a host without HTTPS, is excluded). Below 80% the grade is capped at **B**, below 50% at **C**.

## Targets that do not answer

If no port, web service or TLS endpoint answers, the scan is **Not assessed**: grade `N/A`, no score. A silent target is never graded `A`.

## Limits

The grade is an automated indicator, not a penetration test. Missing findings do not prove the absence of vulnerabilities.
