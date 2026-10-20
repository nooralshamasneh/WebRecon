# REST API v1

Base path: `/api/v1`. Authenticate with a token created under **API tokens** (or `flask --app webrecon create-token USER`):

```
Authorization: Bearer wr_...
```

Responses are JSON. Errors have the form `{"error": "..."}`. Limits: 120 requests/minute per user, 10 scans/hour per user,
3 pending scans per user (all configurable). Status codes: `400` invalid input, `401` not authenticated, `403` not allowed
(for scans: ownership not verified), `404` not found, `429` rate limited (`Retry-After` header on API limits).

## Targets (proof of ownership)

| Method | Path                                   | Description                                                                 |
| ------ | -------------------------------------- | --------------------------------------------------------------------------- |
| `POST` | `/targets` `{"target": "example.com"}` | Create a challenge. Returns `id` and instructions (DNS TXT and token file). |
| `POST` | `/targets/{id}/verify`                 | Check the challenge: `200 {"verified": true}` or `409 {"verified": false}`. |
| `GET`  | `/targets`                             | List your targets and their state.                                          |

## Scans

| Method   | Path                                       | Description                                                                                      |
| -------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `POST`   | `/scans` `{"target": "example.com"}`       | Queue a scan. `202` with the scan object and a `Location` header.                                |
| `GET`    | `/scans?limit=20&offset=0&target=&status=` | List your scans (newest first).                                                                  |
| `GET`    | `/scans/{id}`                              | Status, stage, progress (0-100) and, when `completed`, the full `result`.                        |
| `DELETE` | `/scans/{id}`                              | Delete a scan. `204`.                                                                            |
| `GET`    | `/scans/{id}/report.pdf`                   | PDF report of a completed scan.                                                                  |
| `GET`    | `/compare?a={id}&b={id}`                   | Differences between two completed scans (new/resolved findings, ports, subdomains, score delta). |

Scan status values: `queued`, `running`, `completed`, `failed`.

## Result object (abridged)

```json
{
  "target": "example.com",
  "ip": "93.184.216.34",
  "summary": {
    "status": "assessed",
    "grade": "C",
    "label": "Moderate risk",
    "score": 74,
    "coverage": 100,
    "caps": [],
    "counts": { "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 1 },
    "breakdown": [
      {
        "id": "WR-TLS-004",
        "severity": "high",
        "confidence": "confirmed",
        "points": 15.0
      }
    ]
  },
  "findings": [
    {
      "id": "WR-HDR-003",
      "title": "Missing Content-Security-Policy",
      "severity": "medium",
      "confidence": "confirmed",
      "owasp": "A05",
      "owasp_name": "A05:2021 Security Misconfiguration",
      "asvs": ["V14.4.3"],
      "evidence": [],
      "remediation": "...",
      "references": ["..."]
    }
  ],
  "data": {
    "ports": {},
    "http": {},
    "tls": {},
    "email_auth": {},
    "subdomains": [],
    "emails": [],
    "cve": {},
    "dns": {},
    "whois": {}
  },
  "modules": { "ports": { "status": "ok", "seconds": 4.1 } },
  "notes": []
}
```

A target that did not answer has `summary.status = "not_assessed"` and `grade = "N/A"`.

## Admin

`GET /audit?limit=100` returns the audit log (admin role only). `GET /health` needs
