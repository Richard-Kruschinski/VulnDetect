import unittest
from src.report import to_json, to_html


class TestReport(unittest.TestCase):

    def test_to_json_returns_string(self):
        r = {"a": 1}
        s = to_json(r)
        self.assertIsInstance(s, str)

    def test_to_html_contains_table(self):
        r = {"sqli": [{"param": "id", "evidence": "error"}], "insecure_headers": {"X": {"present": False}}}
        html = to_html(r)
        self.assertIn("<table", html)


if __name__ == "__main__":
    unittest.main()
