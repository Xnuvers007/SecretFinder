#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecretFinder - Advanced Edition
Discover API keys, tokens, and secrets in JavaScript files.

Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
Original Author         : m4ll0k (@m4ll0k2)
Based on                : github.com/m4ll0k/SecretFinder
"""

import sys
if sys.version_info < (3, 8):
    print("[!] SecretFinder requires Python 3.8+")
    sys.exit(1)

# Force UTF-8 stdout/stderr on Windows to avoid cp1252 encode errors
import io as _io
if sys.platform == "win32":
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse
import logging
import os
import re
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

from core import (
    SecretScanner, ScanResult, Severity,
    Fetcher, FetchError,
    resolve_inputs, extract_js_urls, parse_headers, normalize_input,
    cli_output, json_output, csv_output, html_output,
)


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ____                     _   _____ _           _
 / ___|  ___  ___ _ __ ___| |_|  ___(_)_ __   __| | ___ _ __
 \___ \ / _ \/ __| '__/ _ \ __| |_  | | '_ \ / _` |/ _ \ '__|
  ___) |  __/ (__| | |  __/ |_|  _| | | | | | (_| |  __/ |
 |____/ \___|\___|_|  \___|\__|_|   |_|_| |_|\__,_|\___|_|

  Advanced Edition  ·  Rewritten by Xnuvers007
  github.com/Xnuvers007/SecretFinder
"""

COLORS = {
    "red":    "\033[91m", "yellow": "\033[93m",
    "cyan":   "\033[96m", "green":  "\033[92m",
    "white":  "\033[97m", "dim":    "\033[2m",
    "bold":   "\033[1m",  "reset":  "\033[0m",
}
C = COLORS


def _c(color: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_banner(no_color: bool = False) -> None:
    if no_color:
        print(BANNER)
        return
    print(f"{C['cyan']}{C['bold']}{BANNER}{C['reset']}")


# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="SecretFinder",
        description=(
            "SecretFinder Advanced — Discover secrets in JavaScript files.\n"
            "Rewritten by: https://github.com/Xnuvers007/SecretFinder"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input / extraction
    # Input / Output
    io_group = p.add_argument_group("Input / Output")
    # -i / --input / -u / --url are all aliases for the same argument
    io_group.add_argument("-i", "-u", "--input", "--url",
                          dest="input", required=True,
                          metavar="INPUT",
                          help=(
                              "Target to scan. Accepted formats:\n"
                              "  URL        : https://example.com/app.js\n"
                              "  Domain     : example.com  (https auto-prepended)\n"
                              "  Subdomain  : api.example.com\n"
                              "  Path       : example.com/path/app.js\n"
                              "  Local file : /path/to/file.js\n"
                              "  Glob       : /path/to/js/*.js\n"
                              "  Burp XML   : export.xml  (add --burp)"
                          ))
    io_group.add_argument("-o", "--output", default="output/results.html",
                          help="Output path or 'cli' for terminal output (default: output/results.html)")
    io_group.add_argument("--format", choices=["html", "json", "csv", "cli"],
                          default=None,
                          help="Explicit output format (auto-detected from -o extension if not set)")

    # Scheme selection
    scheme_group = p.add_argument_group("Scheme")
    scheme_ex = scheme_group.add_mutually_exclusive_group()
    scheme_ex.add_argument("--https", dest="scheme", action="store_const", const="https",
                           help="Force HTTPS for bare domains (default)")
    scheme_ex.add_argument("--http",  dest="scheme", action="store_const", const="http",
                           help="Force HTTP for bare domains")
    p.set_defaults(scheme="https")

    # Extraction mode
    ext_group = p.add_argument_group("Extraction")
    ext_group.add_argument("-e", "--extract", action="store_true",
                           help="Extract all <script src> JS URLs from the page and scan them")
    ext_group.add_argument("-b", "--burp", action="store_true",
                           help="Input is a Burp Suite XML export file")
    ext_group.add_argument("-g", "--ignore", default="",
                           help="Ignore JS URLs containing these strings (semicolon-separated)")
    ext_group.add_argument("-n", "--only",   default="",
                           help="Only process JS URLs containing these strings (semicolon-separated)")

    # HTTP options
    http_group = p.add_argument_group("HTTP")
    http_group.add_argument("-c", "--cookie",  default="",
                            help='Cookies string (e.g. "session=abc; token=xyz")')
    http_group.add_argument("-H", "--headers", default="",
                            help='Custom headers (e.g. "X-Auth:val\\nX-Token:val2")')
    http_group.add_argument("-p", "--proxy",   default="",
                            help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    http_group.add_argument("--timeout",  type=int, default=15,
                            help="Request timeout in seconds (default: 15)")
    http_group.add_argument("--retries",  type=int, default=3,
                            help="Retry count for failed requests (default: 3)")
    http_group.add_argument("--delay",    type=float, default=0.0,
                            help="Delay between requests in seconds (default: 0)")
    http_group.add_argument("--user-agent", default=None,
                            help="Custom User-Agent string")

    # Scanning options
    scan_group = p.add_argument_group("Scanning")
    scan_group.add_argument("-r", "--regex",  default="",
                            help="Custom regex to add (e.g. 'myapp_[a-z0-9]{32}')")
    scan_group.add_argument("--regex-name", default="custom_regex",
                            help="Name for the custom regex (default: custom_regex)")
    scan_group.add_argument("--severity",
                            choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                            nargs="+", default=None,
                            help="Filter by severity level(s)")
    scan_group.add_argument("--allow-duplicates", action="store_true",
                            help="Do not deduplicate matching values")
    scan_group.add_argument("--fast", action="store_true",
                            help="Skip jsbeautifier (faster but less accurate context)")
    scan_group.add_argument("-t", "--threads", type=int, default=10,
                            help="Number of concurrent threads (default: 10)")

    # Misc
    misc_group = p.add_argument_group("Misc")
    misc_group.add_argument("--no-color",  action="store_true",
                            help="Disable colored terminal output")
    misc_group.add_argument("--no-banner", action="store_true",
                            help="Suppress the ASCII banner")
    misc_group.add_argument("-v", "--verbose", action="store_true",
                            help="Enable verbose/debug logging")
    misc_group.add_argument("--version", action="version",
                            version="SecretFinder Advanced Edition v2.0 — github.com/Xnuvers007/SecretFinder")

    return p


# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_unique_path(path: str) -> str:
    """
    If path is 'cli', return as is.
    Otherwise, ensure directory exists and find a unique filename by appending a number.
    e.g. output/results.html -> output/results2.html
    """
    if path.lower() == "cli":
        return "cli"

    # Ensure directory exists
    dirname = os.path.dirname(path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    if not os.path.exists(path):
        return path

    # Split extension
    base, ext = os.path.splitext(path)
    counter = 2
    while os.path.exists(f"{base}{counter}{ext}"):
        counter += 1
    
    return f"{base}{counter}{ext}"


def detect_format(output: str, explicit_format: Optional[str]) -> str:
    if explicit_format:
        return explicit_format
    if output.lower() == "cli":
        return "cli"
    ext = os.path.splitext(output)[-1].lower()
    return {".json": "json", ".csv": "csv", ".html": "html"}.get(ext, "html")


def validate_regex(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        print(f"[!] Invalid custom regex: {exc}")
        sys.exit(1)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)-8s %(name)s: %(message)s",
    )


# ─── Core scanning logic ──────────────────────────────────────────────────────

def scan_url(url: str, fetcher: Fetcher, scanner: SecretScanner) -> ScanResult:
    """Fetch and scan a single URL."""
    try:
        content = fetcher.get(url)
        return scanner.scan(content, source_url=url)
    except FetchError as exc:
        r = ScanResult(url=url, error=str(exc))
        return r
    except Exception as exc:
        r = ScanResult(url=url, error=f"Unexpected error: {exc}")
        return r


def run_scan(args: argparse.Namespace) -> List[ScanResult]:
    """
    Main scan orchestrator:
    1. Resolve inputs
    2. If --extract, fetch HTML and extract JS URLs
    3. Scan all JS URLs concurrently
    4. Return list of ScanResult
    """

    # Build extra patterns
    extra_patterns = {}
    if args.regex:
        validate_regex(args.regex)
        extra_patterns[args.regex_name] = (
            args.regex, Severity.HIGH, f"Custom: {args.regex_name}"
        )

    # Severity filter
    severity_filter = None
    if args.severity:
        severity_filter = [Severity(s) for s in args.severity]

    # Build scanner
    scanner = SecretScanner(
        extra_patterns=extra_patterns,
        no_duplicates=not args.allow_duplicates,
        fast_mode=args.fast,
        severity_filter=severity_filter,
    )

    # Build fetcher kwargs
    fetch_kwargs = dict(
        cookie=args.cookie,
        proxy=args.proxy,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
    )
    if args.headers:
        fetch_kwargs["headers"] = parse_headers(args.headers)
    if args.user_agent:
        fetch_kwargs["user_agent"] = args.user_agent

    with Fetcher(**fetch_kwargs) as fetcher:

        # Step 1: Resolve raw inputs (passes scheme for bare-domain auto-resolution)
        try:
            raw_inputs = resolve_inputs(
                args.input,
                burp_mode=args.burp,
                scheme=args.scheme,
            )
        except (ValueError, FileNotFoundError) as exc:
            print(f"[!] Input error: {exc}")
            sys.exit(1)

        # Step 2: If extract mode, fetch HTML page and gather JS URLs
        if args.extract:
            all_js_urls: List[str] = []
            for inp in raw_inputs:
                print(f"[+] Extracting JS from: {inp}")
                try:
                    html_content = fetcher.get(inp)
                    js_urls = extract_js_urls(
                        html_content, inp,
                        ignore=args.ignore,
                        only=args.only,
                    )
                    print(f"    └─ Found {len(js_urls)} JS file(s)")
                    all_js_urls.extend(js_urls)
                except FetchError as exc:
                    print(f"[!] Failed to fetch page: {exc}")
            targets = all_js_urls
        elif args.burp:
            # raw_inputs = list of {'js': ..., 'url': ...}
            targets = raw_inputs  # type: ignore
        else:
            targets = raw_inputs

        if not targets:
            print("[!] No targets to scan. Exiting.")
            sys.exit(0)

        # Step 3: Concurrent scanning
        results: List[ScanResult] = []
        total = len(targets)
        done  = 0

        print(f"\n[*] Scanning {total} target(s) with {args.threads} thread(s)...\n")

        def scan_target(target) -> ScanResult:
            if args.burp and isinstance(target, dict):
                url = target.get("url", "burp-item")
                content = target.get("js", "")
                return scanner.scan(content, source_url=url)
            return scan_url(target, fetcher, scanner)

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            future_map = {pool.submit(scan_target, t): t for t in targets}
            for future in as_completed(future_map):
                done += 1
                result = future.result()
                results.append(result)

                # Live progress
                target_label = result.url[:60]
                count  = len(result.findings)
                crits  = len(result.critical)
                status = ""
                if result.error:
                    status = f"\033[91m[ERR]\033[0m {result.error[:60]}"
                elif count == 0:
                    status = "\033[2m[~] No findings\033[0m"
                else:
                    status = (
                        f"\033[92m[+] {count} finding(s)\033[0m"
                        + (f" \033[91m| {crits} CRITICAL\033[0m" if crits else "")
                    )
                print(f"  [{done:>3}/{total}] {target_label:<62} {status}")

    return results


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main() -> None:
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda *_: (print("\n[!] Aborted."), sys.exit(0)))

    parser  = build_parser()

    # Show help and exit if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args    = parser.parse_args()
    
    # Generate unique output path if not 'cli'
    args.output = get_unique_path(args.output)

    setup_logging(args.verbose)

    if not args.no_banner:
        print_banner(no_color=args.no_color)

    fmt = detect_format(args.output, args.format)

    # ── Run ──
    results = run_scan(args)

    # ── Summary ──
    total    = sum(len(r.findings) for r in results)
    critical = sum(len(r.critical) for r in results)
    high     = sum(len(r.high)     for r in results)
    errors   = sum(1 for r in results if r.error)

    print(f"\n{'─'*60}")
    print(f"  Targets scanned : {len(results)}")
    print(f"  Total findings  : {total}")
    if critical:
        print(f"  \033[91mCRITICAL        : {critical}\033[0m")
    if high:
        print(f"  \033[31mHIGH            : {high}\033[0m")
    if errors:
        print(f"  \033[33mErrors          : {errors}\033[0m")
    print(f"{'─'*60}\n")

    # ── Output ──
    if fmt == "cli":
        cli_output(results, use_color=not args.no_color)
    elif fmt == "json":
        json_output(results, args.output)
    elif fmt == "csv":
        csv_output(results, args.output)
    else:
        html_output(results, args.output)


if __name__ == "__main__":
    main()
