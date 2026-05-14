"""
SecretFinder - Core Package
"""
from .scanner import SecretScanner, ScanResult, Finding
from .patterns import Severity, PATTERNS
from .fetcher import Fetcher, FetchError
from .input_parser import resolve_inputs, extract_js_urls, parse_headers, normalize_input
from .output import cli_output, json_output, csv_output, html_output

__all__ = [
    "SecretScanner", "ScanResult", "Finding",
    "Severity", "PATTERNS",
    "Fetcher", "FetchError",
    "resolve_inputs", "extract_js_urls", "parse_headers",
    "cli_output", "json_output", "csv_output", "html_output",
]
