# Security Policy

## Responsible use

WebRecon performs active reconnaissance (port scanning, service detection,
HTTP probing, DNS brute-forcing). **Only scan systems you own or have explicit
written permission to test.** Unauthorized scanning may be illegal in your
jurisdiction. The authors accept no liability for misuse.

For practice, use targets that explicitly allow scanning, such as
`scanme.nmap.org`, or your own lab environment.

## Built-in safeguards

- The target must be a valid domain or IP address (no URLs with options, no shell input).
- Loopback, private, link-local and reserved addresses are rejected (SSRF protection).
- The scanner never passes user input to a shell; nmap is invoked with an argument list and `--`.
- The web UI requires an explicit authorization confirmation before each scan.
- The server binds to `127.0.0.1` and runs with debug mode off by default.

## Reporting a vulnerability

If you find a security issue in WebRecon itself, please open a private
security advisory on GitHub (Security tab > "Report a vulnerability")
instead of a public issue. Include steps to reproduce and the affected version.
