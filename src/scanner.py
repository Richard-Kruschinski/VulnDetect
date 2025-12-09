"""Main Web Application Security Scanner (WASS).

This module coordinates checks implemented in `src.utils` and `src.webapp_scanner`.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from copy import deepcopy
from .utils import HTTPClient, find_forms, submit_form
from .webapp_scanner import ExtraWebAppScanner


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
        self.extra = ExtraWebAppScanner(base_url, timeout=timeout)

    def _fetch(self, url):
        return self.client.get(url)

    def check_insecure_headers(self):
        resp = self._fetch(self.base_url)
        headers = getattr(resp, "headers", {}) or {}
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
        findings = {"reflected": [], "stored": []}
        payload = "<script>alert('xss')</script>"

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
                if resp and payload in (getattr(resp, "text", "") or ""):
                    findings["reflected"].append({"param": param, "url": test_url})

        base_resp = self._fetch(self.base_url)
        forms = find_forms(getattr(base_resp, "text", "") or "", self.base_url)
        for form in forms:
            text_inputs = [i for i in form.get("inputs", []) if i.get("type") in ("text", "search", "textarea", "")]
            if not text_inputs:
                continue
            payloads = {inp["name"]: payload for inp in text_inputs}
            submit_resp = submit_form(self.client, form, payloads=payloads)
            check_resp = self.client.get(form["action"]) if form.get("action") else submit_resp
            if check_resp and payload in (getattr(check_resp, "text", "") or ""):
                findings["stored"].append({"form_action": form.get("action"), "inputs": [i["name"] for i in text_inputs]})

        return findings

    def check_sqli(self):
        findings = []
        payloads = ["'", "' OR '1'='1", '" OR "1"="1', "'; --", " OR 1=1--"]

        parsed = urlparse(self.base_url)
        qs = parse_qs(parsed.query)
        baseline_resp = self._fetch(self.base_url)
        baseline_text = getattr(baseline_resp, "text", "") or ""

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
                text = getattr(resp, "text", "") or ""
                lower = text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in lower:
                        findings.append({"param": param, "payload": p, "evidence": pattern})
                        break
                else:
                    if abs(len(text) - len(baseline_text)) > max(50, len(baseline_text) * 0.1):
                        findings.append({"param": param, "payload": p, "evidence": "content-length-diff"})
                if any(f["param"] == param for f in findings):
                    break

        return findings

    def check_password_policy(self):
        resp = self._fetch(self.base_url)
        forms = find_forms(getattr(resp, "text", "") or "", self.base_url)
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
        return {
            "insecure_headers": self.check_insecure_headers(),
            "xss": self.check_xss(),
            "sqli": self.check_sqli(),
            "password_policy": self.check_password_policy(),
            "directory_traversal": self.extra.check_directory_traversal(),
            "session_management": self.extra.check_session_management(),
            "rate_limiting": self.extra.check_rate_limiting(),
            "csrf": self.extra.check_csrf(),
        }


__all__ = ["WebAppScanner"]
