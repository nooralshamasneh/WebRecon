# Contributing

Thanks for helping! Please keep changes focused and tested.

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m unittest discover -s tests -t . -v            # all tests must pass
python -m ruff check .                                  # lint must be clean
```

- Add a test for every new check or bug fix (tests never need internet; mock DNS/HTTP/NVD as the existing tests do).
- New findings go in `webrecon/findings.py` with an OWASP Top 10 mapping, severity, remediation and references,
  then regenerate the docs: `python -m webrecon.findings > docs/OWASP_MAPPING.md`.
- Never add checks that exploit a target. WebRecon is detection-only.
- Dependency updates: regenerate `requirements.lock` (`pip freeze > requirements.lock`) in a clean virtualenv.
