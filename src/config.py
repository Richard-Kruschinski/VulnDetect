"""Configuration handling for the scanner."""
import json
import os


def load_config(path=None):
    """Load `config.json` from project root by default.

    Returns a dict of settings. If file missing, returns sensible defaults.
    """
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {
            "timeout": 10,
            "max_token_lifetime_seconds": 3600,
            "allowed_algorithms": ["HS256", "RS256"],
        }


def get_config():
    return load_config()
