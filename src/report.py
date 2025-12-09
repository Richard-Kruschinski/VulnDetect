"""Reporting utilities: JSON and HTML report generation."""
import json
from html import escape
from datetime import datetime


def to_json(report, path=None):
    s = json.dumps(report, indent=2, ensure_ascii=False)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(s)
    return s


def to_html(report, path=None, title="VulnDetect Scan Report"):
    now = datetime.utcnow().isoformat() + "Z"
    html_parts = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        f"<meta charset=\"utf-8\"><title>{escape(title)}</title>",
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f4f4;text-align:left}</style>",
        "</head>",
        "<body>",
        f"<h1>{escape(title)}</h1>",
        f"<p>Generated: {escape(now)}</p>",
    ]

    html_parts.append("<h2>Summary</h2>")
    html_parts.append("<ul>")
    for k, v in report.items():
        cnt = None
        if isinstance(v, list):
            cnt = len(v)
        elif isinstance(v, dict):
            cnt = sum(len(x) if isinstance(x, list) else 1 for x in v.values())
        html_parts.append(f"<li><strong>{escape(str(k))}</strong>: {escape(str(cnt))}</li>")
    html_parts.append("</ul>")

    for section, data in report.items():
        html_parts.append(f"<h2>{escape(str(section))}</h2>")
        if isinstance(data, list):
            if not data:
                html_parts.append("<p>No findings.</p>")
                continue
            # build table from keys of first item
            keys = set()
            for item in data:
                if isinstance(item, dict):
                    keys.update(item.keys())
            keys = list(keys)
            html_parts.append("<table>")
            html_parts.append("<tr>" + "".join(f"<th>{escape(k)}</th>" for k in keys) + "</tr>")
            for item in data:
                if isinstance(item, dict):
                    html_parts.append("<tr>" + "".join(f"<td>{escape(str(item.get(k, '')))}</td>" for k in keys) + "</tr>")
            html_parts.append("</table>")
        elif isinstance(data, dict):
            html_parts.append("<table>")
            html_parts.append("<tr><th>Key</th><th>Value</th></tr>")
            for k, v in data.items():
                html_parts.append(f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>")
            html_parts.append("</table>")
        else:
            html_parts.append(f"<pre>{escape(str(data))}</pre>")

    html_parts.append("</body></html>")
    out = "\n".join(html_parts)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out)
    return out
