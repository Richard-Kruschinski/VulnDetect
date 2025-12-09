"""CLI entrypoint for running the scanner."""
import argparse
from .scanner import WebAppScanner
from .report import to_json, to_html
from .config import get_config


def main():
    parser = argparse.ArgumentParser(description="VulnDetect - Web Application Security Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-j", "--json", dest="json_path", help="Write JSON report to file")
    parser.add_argument("-H", "--html", dest="html_path", help="Write HTML report to file")
    args = parser.parse_args()

    cfg = get_config()
    timeout = cfg.get("timeout", 10)
    scanner = WebAppScanner(args.url, timeout=timeout)
    report = scanner.run_all_checks()

    if args.json_path:
        to_json(report, path=args.json_path)
        print(f"Wrote JSON report to {args.json_path}")
    if args.html_path:
        to_html(report, path=args.html_path)
        print(f"Wrote HTML report to {args.html_path}")

    if not args.json_path and not args.html_path:
        print("Scan complete. Use -j or -H to write reports.")


if __name__ == "__main__":
    main()
