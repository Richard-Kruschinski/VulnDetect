"""Additional web application security checks.

Provides Directory Traversal, Session Management, Rate-Limiting and CSRF checks.
"""
from urllib.parse import urljoin
from .utils import HTTPClient, find_forms, submit_form


class ExtraWebAppScanner:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url
        self.client = HTTPClient(timeout=timeout)

    def check_directory_traversal(self):
        """Attempt simple directory traversal checks by requesting common traversal payloads.

        Returns list of findings with `payload` and `evidence` (e.g., known file text).
        """
        payloads = ["../etc/passwd", r"..\..\..\windows\system32\drivers\etc\hosts"]
        findings = []
        for p in payloads:
            url = urljoin(self.base_url, p)
            try:
                resp = self.client.get(url)
                text = resp.text or ""
                # simple heuristics
                if "root:" in text or "localhost" in text:
                    findings.append({"payload": p, "url": url, "evidence": text[:200]})
            except Exception:
                continue
        return findings

    def check_session_management(self):
        """Check basic session cookie flags like `Secure` and `HttpOnly`.

        Returns dict cookie_name -> {secure: bool, httponly: bool}
        """
        try:
            resp = self.client.get(self.base_url)
        except Exception:
            return {}
        cookies = getattr(resp, "cookies", None)
        results = {}
        if not cookies:
            return results
        if hasattr(cookies, "items"):
            try:
                for name, c in cookies.items():
                    secure = getattr(c, "secure", False)
                    httponly = False
                    if hasattr(c, "_rest"):
                        httponly = bool(c._rest.get("HttpOnly"))
                    results[name] = {"secure": secure, "httponly": httponly}
            except Exception:
                return {}
        else:
            try:
                for name in dir(cookies):
                    if name.startswith("_"):
                        continue
                    attr = getattr(cookies, name)
                    if callable(attr):
                        continue
                    results[name] = {"secure": False, "httponly": False}
            except Exception:
                return {}
        return results

    def check_rate_limiting(self, endpoint="/login", attempts=10, delay_seconds=0):
        """Simulate repeated requests to detect simple rate-limiting behavior.

        Returns a dict with `attempts` and `status_codes` summary.
        """
        statuses = []
        url = urljoin(self.base_url, endpoint)
        for i in range(attempts):
            try:
                resp = self.client.post(url, data={"username": "test", "password": "bad"})
                statuses.append(getattr(resp, "status_code", None))
            except Exception:
                statuses.append(None)
        return {"attempts": attempts, "status_codes": statuses}

    def check_csrf(self):
        """Check for anti-CSRF tokens in forms and common headers.

        Returns dict with forms missing tokens and CSRF header presence.
        """
        try:
            resp = self.client.get(self.base_url)
        except Exception:
            return {"forms_missing_token": [], "csrf_headers": {}}
        forms = find_forms(resp.text or "", self.base_url)
        missing = []
        for f in forms:
            inputs = f.get("inputs", [])
            has_token = any(i.get("name", "").lower() in ("csrf_token", "csrfmiddlewaretoken", "_csrf") for i in inputs)
            if not has_token:
                missing.append({"action": f.get("action"), "method": f.get("method")})
        headers = getattr(resp, "headers", {}) or {}
        csrf_headers = {"x-csrf-token": headers.get("X-CSRF-Token"), "x-requested-with": headers.get("X-Requested-With")}
        return {"forms_missing_token": missing, "csrf_headers": csrf_headers}
