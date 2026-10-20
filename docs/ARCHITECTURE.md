# Architecture

```
Browser / API client
        |  HTTPS (reverse proxy)
        v
 Flask app  (web.py, api.py)        auth, CSRF, rate limits, audit log
        |  submit_scan(): validate -> SSRF check -> ownership proof -> quota -> INSERT scans(status='queued')
        v
 SQLite (db.py)  <-------------------------------------------+
   users, api_tokens, scans, verifications, audit_log,        |
   cve_cache                                                  |
        ^                                                     |
        | claim (atomic UPDATE ... WHERE status='queued')     | progress / result
 Worker threads (jobs.py) ----> scanner.run_scan() ----------+
                                   |
        ScanContext (DNS pinning)  |   modules: dns, whois, subdomains, ports (nmap), http headers,
        SafeFetcher (pinned IP,    |   cookies/CORS, tech fingerprint, sensitive paths, TLS,
        redirect validation)       |   SPF/DKIM/DMARC, NVD CVE correlation
                                   v
                     findings.py (catalogue + OWASP mapping)  ->  scoring.py (severity model)  ->  report.py (PDF)
```

## Key decisions

- **Database-backed queue.** A scan is a row; workers claim it with an atomic `UPDATE ... WHERE status='queued'`. Jobs survive restarts,
  stale `running` jobs (no heartbeat) are marked failed, and the UI shows live progress by polling `GET /api/v1/scans/{id}`.
  The claim step is the only coupling, so the workers can be replaced by Celery/RQ without touching the scanner.
- **SQLite** keeps deployment to one container. Switching to PostgreSQL means replacing `db.py`.
- **One IP per scan.** `ScanContext` resolves each hostname once; HTTP, TLS and nmap all connect to that IP.
- **Findings are data.** Modules return findings from one catalogue, so OWASP/ASVS mapping, severities and remediation text live in one file
  and the docs are generated from it.
- **Modules fail independently.** A failing module is recorded (`modules` in the result) and lowers _coverage_ instead of aborting the scan.
- **No files on disk for reports.** PDFs are rendered in memory on demand.

## Scaling and limits

Run one process (rate limits and workers are per process). For more throughput raise `WEBRECON_WORKERS`.
Multi-host deployments need a shared rate-limit store and PostgreSQL.
