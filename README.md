# VulnDetect — Web Application Security Scanner (WASS)

VulnDetect is a lightweight web application security scanner that checks for common issues such as SQL Injection, XSS, insecure HTTP headers, weak password policies, directory traversal, session management issues, rate-limiting weaknesses and missing CSRF protections.

Repository layout:

- `src/` — package code
	- `src/scanner.py` — main scanner
	- `src/webapp_scanner.py` — extra security checks (directory traversal, session, rate-limiting, CSRF)
	- `src/utils.py` — HTTP client and form helpers
	- `src/config.py` — configuration loader for `config.json`
	- `src/report.py` — JSON and HTML report generation
	- `src/cli.py` — CLI entrypoint using `argparse`
- `tests/` — unit tests using `unittest` + `unittest.mock`
- `config.json` — default scanner configuration
- `requirements.txt` — Python dependencies (`requests`, `beautifulsoup4`)

Quick start (PowerShell):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```

Run the scanner from the package CLI (writes nothing by default):

```powershell
python -m src.cli "http://example.com/page?param=1"
```

Write JSON and/or HTML reports:

```powershell
python -m src.cli "http://example.com/page?param=1" -j report.json -H report.html
```

Run the test-suite (discovery will run tests in `tests`):

```powershell
python -m unittest discover -v -s tests -p "test_*.py"
```

Notes:
- Tests use `unittest.mock` to patch network calls so they run offline and quickly.
- The HTML report is a simple tabular summary suitable for quick review.