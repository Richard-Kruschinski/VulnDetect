import unittest
from unittest.mock import patch, Mock
from src.webapp_scanner import ExtraWebAppScanner


class TestExtraScans(unittest.TestCase):

    def setUp(self):
        self.url = "http://example.com/"
        self.scanner = ExtraWebAppScanner(self.url)

    @patch("src.utils.requests.Session.get")
    def test_directory_traversal_no_findings(self, mock_get):
        base = Mock()
        base.text = "normal"
        mock_get.return_value = base

        findings = self.scanner.check_directory_traversal()
        self.assertIsInstance(findings, list)

    @patch("src.utils.requests.Session.get")
    def test_check_csrf_detects_missing(self, mock_get):
        html = '<form action="/transfer" method="post"><input type="text" name="amount"></form>'
        resp = Mock()
        resp.text = html
        resp.headers = {}
        mock_get.return_value = resp

        res = self.scanner.check_csrf()
        self.assertIn("forms_missing_token", res)

    @patch("src.utils.requests.Session.post")
    def test_rate_limiting_collects_statuses(self, mock_post):
        r = Mock()
        r.status_code = 200
        mock_post.return_value = r

        res = self.scanner.check_rate_limiting(attempts=3)
        self.assertEqual(res["attempts"], 3)
        self.assertEqual(len(res["status_codes"]), 3)


if __name__ == "__main__":
    unittest.main()
