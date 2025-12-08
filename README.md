# Web Application Security Scanner (WASS)

Simple Python-based scanner that performs basic checks for SQL Injection, XSS, insecure HTTP headers, and password strength checks.

Files:
- `scanner.py` — main scanner implementation and CLI
- `utils.py` — HTTP helpers and HTML form parsing
- `tests.py` — unit tests using `unittest` and mocks
- `requirements.txt` — external dependencies

Quick start:

1. Create a virtualenv and install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

2. Run scanner from CLI:

```powershell
python scanner.py "http://example.com/page?param=1"
```

You can also write a JSON report to a file using `--json`:

```powershell
python scanner.py "http://example.com/page?param=1" --json report.json
```

3. Run tests:

```powershell
python -m unittest tests.py
```

Notes:
- This project provides simple heuristic checks and is intended as an educational starting point, not a production-grade scanner.
