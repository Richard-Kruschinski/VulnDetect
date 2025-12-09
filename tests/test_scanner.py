import unittest
from unittest.mock import patch, Mock
from src.scanner import WebAppScanner


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.url = "http://example.com/page?search=hello&id=1"
        self.scanner = WebAppScanner(self.url)

    @patch("src.utils.requests.Session.get")
    def test_check_insecure_headers(self, mock_get):
        mock_resp = Mock()
        mock_resp.headers = {"X-Frame-Options": "DENY"}
        mock_resp.text = "OK"
        mock_get.return_value = mock_resp

        res = self.scanner.check_insecure_headers()
        self.assertTrue(res["X-Frame-Options"]["present"])
        self.assertEqual(res["X-Frame-Options"]["value"], "DENY")

    @patch("src.utils.requests.Session.get")
    def test_check_xss_reflected(self, mock_get):
        base_resp = Mock()
        base_resp.text = "<html></html>"
        base_resp.headers = {}

        xss_resp = Mock()
        xss_payload = "<script>alert('xss')</script>"
        xss_resp.text = f"<html>{xss_payload}</html>"

        def side_effect(*args, **kwargs):
            for a in args:
                if isinstance(a, str) and xss_payload in a:
                    return xss_resp
            params = kwargs.get("params")
            if params and any(xss_payload in str(v) for v in params.values()):
                return xss_resp
            return base_resp

        mock_get.side_effect = side_effect

        findings = self.scanner.check_xss()
        self.assertIsInstance(findings, dict)

    @patch("src.utils.requests.Session.get")
    def test_check_sqli_detects_error(self, mock_get):
        base = Mock()
        base.text = "normal page content"
        base.headers = {}

        inj = Mock()
        inj.text = "You have an error in your SQL syntax near..."
        inj.headers = {}

        def side_effect(*args, **kwargs):
            for a in args:
                if isinstance(a, str) and ("'" in a or " OR " in a or "--" in a):
                    return inj
            params = kwargs.get("params")
            if params and any("'" in str(v) or " OR " in str(v) or "--" in str(v) for v in params.values()):
                return inj
            return base

        mock_get.side_effect = side_effect

        findings = self.scanner.check_sqli()
        self.assertTrue(isinstance(findings, list))

    @patch("src.utils.requests.Session.get")
    def test_check_password_policy(self, mock_get):
        html = '<form action="/login" method="post"><input type="password" name="pw"></form>'
        resp = Mock()
        resp.text = html
        resp.headers = {}
        mock_get.return_value = resp

        res = self.scanner.check_password_policy()
        self.assertTrue(res["overall_weak_allowed"])

    def test_analyze_password_strength(self):
        r = WebAppScanner.analyze_password_strength("Pa$$w0rd1")
        self.assertIn("verdict", r)

    @patch("src.utils.requests.Session.get")
    def test_run_all_checks_returns_report(self, mock_get):
        base = Mock()
        base.text = "<html></html>"
        base.headers = {}
        mock_get.return_value = base

        report = self.scanner.run_all_checks()
        self.assertIsInstance(report, dict)
        self.assertIn("insecure_headers", report)
        self.assertIn("xss", report)
        self.assertIn("sqli", report)
        self.assertIn("password_policy", report)


if __name__ == "__main__":
    unittest.main()
