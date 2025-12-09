import unittest
from src.utils import find_forms, submit_form, HTTPClient
from unittest.mock import Mock


class TestUtils(unittest.TestCase):

    def test_find_forms_parses_simple_form(self):
        html = '<form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>'
        forms = find_forms(html, "http://example.com")
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f["method"], "post")
        self.assertEqual(f["inputs"][0]["name"], "user")

    def test_submit_form_uses_payloads(self):
        client = Mock()
        form = {"action": "http://example.com/login", "method": "post", "inputs": [{"name": "user", "type": "text", "value": ""}, {"name": "pw", "type": "password", "value": ""}]}
        resp = Mock()
        client.post.return_value = resp
        r = submit_form(client, form, payloads={"user": "alice", "pw": "secret"})
        client.post.assert_called_once()
        self.assertIs(r, resp)


if __name__ == "__main__":
    unittest.main()
