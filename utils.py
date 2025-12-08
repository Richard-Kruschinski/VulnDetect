"""Utility helpers for HTTP operations and HTML form parsing."""
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


class HTTPClient:
    """Simple HTTP client wrapper around requests.Session.

    Provides `get` and `post` helpers that return the underlying
    `requests.Response` object to keep scanner logic flexible.
    """

    def __init__(self, timeout=10):
        self.session = requests.Session()
        self.timeout = timeout

    def get(self, url, params=None, headers=None):
        """Perform an HTTP GET and return the Response."""
        return self.session.get(url, params=params, headers=headers, timeout=self.timeout)

    def post(self, url, data=None, json=None, headers=None):
        """Perform an HTTP POST and return the Response."""
        return self.session.post(url, data=data, json=json, headers=headers, timeout=self.timeout)


def find_forms(html, base_url):
    """Parse HTML and return a list of form descriptors.

    Each form descriptor is a dict: {"action", "method", "inputs": [{"name","type","value"}, ...]}
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        action = urljoin(base_url, action)
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type") or ("textarea" if inp.name == "textarea" else "text")
            value = inp.get("value") or ""
            inputs.append({"name": name, "type": typ, "value": value, "attrs": dict(inp.attrs)})
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def submit_form(client, form, payloads=None):
    """Submit a parsed form using the provided `HTTPClient`.

    `payloads` should be a dict mapping input names to values. For inputs not
    present in `payloads`, the function will use the form's default value.
    Returns the `requests.Response` from the submission.
    """
    payloads = payloads or {}
    data = {}
    for inp in form.get("inputs", []):
        name = inp["name"]
        if name in payloads:
            data[name] = payloads[name]
        else:
            data[name] = inp.get("value", "")

    if form.get("method") == "post":
        return client.post(form["action"], data=data)
    else:
        return client.get(form["action"], params=data)
