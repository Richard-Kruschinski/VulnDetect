"""Web Application Security Scanner (WASS).

This module provides an object-oriented scanner that can check for:
- SQL Injection
- Cross-Site Scripting (reflected & stored)
- Insecure HTTP headers
- Weak password acceptance in forms

The scanner uses `utils.HTTPClient` and HTML helpers in `utils.py`.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy
from bs4 import BeautifulSoup
from utils import HTTPClient, find_forms, submit_form


SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
]


class WebAppScanner:
    """High-level scanner that exposes checks for common web vulnerabilities."""

    def __init__(self, base_url, timeout=10):
        self.base_url = base_url
        self.client = HTTPClient(timeout=timeout)

    def _fetch(self, url):
        return self.client.get(url)

    def check_insecure_headers(self):
        """Check for presence (and values) of common security headers.

        Returns a dict mapping header name -> (present: bool, value or None).
        """
        resp = self._fetch(self.base_url)
        headers = resp.headers or {}
        checks = {}
        header_names = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-XSS-Protection",
        ]
        for h in header_names:
            checks[h] = {"present": h in headers, "value": headers.get(h)}
        return checks

    def check_xss(self):
        """Perform simple reflected and stored XSS checks.

        - Reflected XSS: inject a script payload into each query parameter and
          check if it appears in the response HTML.
        - Stored XSS: find forms that accept text and try to submit a payload,
          then re-request the form's action URL and look for persistent reflection.

        Returns a dict with keys `reflected` and `stored`, each a list of findings.
        """
        findings = {"reflected": [], "stored": []}
        payload = "<script>alert('xss')</script>"

        # Reflected XSS via query params
        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        if qs:
            for param in qs:
                mod_qs = deepcopy(qs)
                mod_qs[param] = [payload]
                new_query = urlencode({k: v[0] for k, v in mod_qs.items()})
                new_parsed = parsed._replace(query=new_query)
                test_url = urlunparse(new_parsed)
                resp = self._fetch(test_url)
                if resp and payload in (resp.text or ""):
                    findings["reflected"].append({"param": param, "url": test_url})

        # Stored XSS: find forms and attempt to post payload then check persistence
        base_resp = self._fetch(self.base_url)
        forms = find_forms(base_resp.text or "", self.base_url)
        for form in forms:
            # only attempt forms that accept text-like inputs
            text_inputs = [i for i in form.get("inputs", []) if i.get("type") in ("text", "search", "textarea", "")]
            if not text_inputs:
                continue
            payloads = {inp["name"]: payload for inp in text_inputs}
            submit_resp = submit_form(self.client, form, payloads=payloads)
            # fetch action page to see if payload stored/reflected
            check_resp = self.client.get(form["action"]) if form.get("action") else submit_resp
            if check_resp and payload in (check_resp.text or ""):
                findings["stored"].append({"form_action": form.get("action"), "inputs": [i["name"] for i in text_inputs]})

        return findings

    def check_sqli(self):
        """Basic SQL Injection checks.

        Strategy:
        - If URL has query parameters, inject SQL payloads and look for SQL errors
          or significant differences in response content length.
        - Return list of vulnerable params with evidence.
        """
        findings = []
        payloads = ["'", "' OR '1'='1", '" OR "1"="1', "'; --", " OR 1=1--"]

        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        baseline_resp = self._fetch(self.base_url)
        baseline_text = baseline_resp.text or ""

        if not qs:
            return findings

        for param in qs:
            for p in payloads:
                mod_qs = deepcopy(qs)
                mod_qs[param] = [p]
                new_query = urlencode({k: v[0] for k, v in mod_qs.items()})
                new_parsed = parsed._replace(query=new_query)
                test_url = urlunparse(new_parsed)
                resp = self._fetch(test_url)
                text = resp.text or ""
                lower = text.lower()
                # check for SQL error messages
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in lower:
                        findings.append({"param": param, "payload": p, "evidence": pattern})
                        break
                else:
                    # heuristics: large content change may indicate injectable behavior
                    if abs(len(text) - len(baseline_text)) > max(50, len(baseline_text) * 0.1):
                        findings.append({"param": param, "payload": p, "evidence": "content-length-diff"})
                # if we've found evidence for this param, stop testing more payloads
                if any(f["param"] == param for f in findings):
                    break

        return findings

    def check_password_policy(self):
        """Analyze forms to see if password inputs allow weak passwords.

        Criteria used:
        - If password input has `minlength` attribute less than 8 -> weak allowed.
        - If no password inputs present -> report no password forms.
        - If inputs lack `pattern` or client-side constraints -> may accept weak passwords.

        Returns a dict with `forms` list and a simple `overall` verdict.
        """
        resp = self._fetch(self.base_url)
        forms = find_forms(resp.text or "", self.base_url)
        results = []
        overall_weak_allowed = False
        for form in forms:
            pw_inputs = [i for i in form.get("inputs", []) if i.get("type") == "password"]
            if not pw_inputs:
                continue
            for inp in pw_inputs:
                attrs = inp.get("attrs", {})
                minlength = attrs.get("minlength")
                pattern = attrs.get("pattern")
                info = {"input": inp.get("name"), "minlength": minlength, "pattern": pattern}
                if not minlength:
                    info["weak_allowed"] = True
                    overall_weak_allowed = True
                else:
                    try:
                        if int(minlength) < 8:
                            info["weak_allowed"] = True
                            overall_weak_allowed = True
                        else:
                            info["weak_allowed"] = False
                    except Exception:
                        info["weak_allowed"] = True
                        overall_weak_allowed = True
                results.append(info)

        return {"forms": results, "overall_weak_allowed": overall_weak_allowed}

    @staticmethod
    def analyze_password_strength(password):
        """Return a simple score and verdict for a given password string.

        Score is between 0..4 based on length and character classes.
        """
        score = 0
        if len(password) >= 8:
            score += 1
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;':,./<>?" for c in password):
            score += 1
        verdict = "weak" if score < 3 else "ok" if score == 3 else "strong"
        return {"score": score, "verdict": verdict}


    def run_all_checks(self):
        """Run all built-in checks and return a consolidated report dict."""
        return {
            "insecure_headers": self.check_insecure_headers(),
            "xss": self.check_xss(),
            "sqli": self.check_sqli(),
            "password_policy": self.check_password_policy(),
        }


def run_cli():
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Simple Web Application Security Scanner")
    parser.add_argument("url", help="Target URL to scan (include query string if required)")
    parser.add_argument("-j", "--json", dest="json", help="Write JSON report to file (path)")
    args = parser.parse_args()
    s = WebAppScanner(args.url)
    # Run combined checks
    report = s.run_all_checks()

    # If JSON output requested, write to file and exit
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            print(f"JSON report written to {args.json}")
        except Exception as e:
            print(f"Failed to write JSON report: {e}")
        return

    # Human-readable output (backwards-compatible)
    print("Checking insecure headers...")
    headers = report.get("insecure_headers", {})
    for h, info in headers.items():
        print(f"{h}: present={info['present']} value={info['value']}")

    print("\nRunning XSS checks...")
    print(report.get("xss", {}))

    print("\nRunning SQLi checks...")
    print(report.get("sqli", []))

    print("\nChecking password policy...")
    print(report.get("password_policy", {}))


if __name__ == "__main__":
    run_cli()
