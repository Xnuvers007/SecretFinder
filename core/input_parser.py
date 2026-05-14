#!/usr/bin/env python3
"""
SecretFinder - Input Parser & JS Extractor
Handles all input types: URLs, local files, glob patterns, Burp XML exports.
Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
"""

from __future__ import annotations

import base64
import glob
import logging
import os
import xml.etree.ElementTree as ET
from typing import List, Union
from urllib.parse import urlparse

from lxml import html as lhtml

logger = logging.getLogger("secretfinder.input_parser")

SCHEMES = ("http://", "https://", "ftp://", "ftps://", "file://")

import re as _re

# ── Smart input recognition patterns ────────────────────────────────────────

# IPv4 with optional port and path
# e.g.  192.168.1.1  /  10.0.0.1:8080  /  10.0.0.1:8080/api/v1
_IPV4_RE = _re.compile(
    r'^(?P<ip>(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))'
    r'(?::(?P<port>\d{1,5}))?'
    r'(?P<path>/[^\s]*)?$'
)

# IPv6 with optional port — must be wrapped in brackets for port
# e.g.  [::1]  /  [::1]:8080  /  [fe80::1%25eth0]:443/path
_IPV6_RE = _re.compile(
    r'^\[(?P<ip>[0-9a-fA-F:.%]+)\]'
    r'(?::(?P<port>\d{1,5}))?'
    r'(?P<path>/[^\s]*)?$'
)

# Bare domain / multi-level subdomain / domain with port and optional path
# Handles: example.com, sub.example.com, www.deep.sub.example.co.uk,
#          example.com:8443, api.example.com:3000/v2/endpoint
_DOMAIN_RE = _re.compile(
    r'^(?P<host>'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'  # labels
    r'[a-zA-Z]{2,63}'                                              # TLD
    r')'
    r'(?::(?P<port>\d{1,5}))?'                                    # optional :port
    r'(?P<path>/[^\s]*)?$'                                        # optional path
)


def _is_ipv4(raw: str) -> bool:
    return bool(_IPV4_RE.match(raw))


def _is_ipv6(raw: str) -> bool:
    return bool(_IPV6_RE.match(raw))


def _is_domain(raw: str) -> bool:
    return bool(_DOMAIN_RE.match(raw))


def normalize_input(raw: str, scheme: str = "https") -> str:
    """
    Smart normalizer — converts any user input into a full URL.

    Supported bare inputs (no scheme needed):
      Domain          : example.com
      Multi-subdomain : www.api.staging.example.co.uk
      Domain + port   : example.com:8443
      Domain + path   : example.com/admin/login
      Domain+port+path: example.com:8080/api/v1
      IPv4            : 192.168.1.1
      IPv4 + port     : 192.168.1.1:8080
      IPv4 + path     : 10.0.0.1:8080/api
      IPv6 (bracket)  : [::1]:8080
      view-source:    : view-source:https://example.com/app.js
    """
    raw = raw.strip()

    # Strip browser view-source prefix
    if raw.startswith("view-source:"):
        raw = raw[12:].strip()

    # Already has a scheme — return as-is
    if raw.startswith(SCHEMES):
        return raw

    # IPv6 bracket notation: [::1]:8080 or [::1]/path
    if _is_ipv6(raw):
        logger.debug("IPv6 detected, prepending '%s://' to: %s", scheme, raw)
        return f"{scheme}://{raw}"

    # Bare IPv4 (with optional port/path)
    if _is_ipv4(raw):
        logger.debug("IPv4 detected, prepending '%s://' to: %s", scheme, raw)
        return f"{scheme}://{raw}"

    # Domain / subdomain (with optional port/path)
    if _is_domain(raw):
        logger.debug("Domain detected, prepending '%s://' to: %s", scheme, raw)
        return f"{scheme}://{raw}"

    # Can't auto-resolve — return unchanged (will fail later with a clear message)
    return raw


def parse_headers(raw: str) -> dict:
    """Parse 'Name:Value\\nName2:Value2' into a dict."""
    headers = {}
    for line in raw.replace("\\n", "\n").split("\n"):
        line = line.strip()
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def resolve_inputs(
    raw_input: str,
    burp_mode: bool = False,
    scheme: str = "https",
) -> List[Union[str, dict]]:
    """
    Resolve raw CLI input into a list of URLs or Burp JS dicts.

    Supported input types:
      - Full URL:        https://example.com/app.js
      - Bare domain:    example.com  (auto-prepends scheme, default https)
      - Local file:     /path/to/file.js  or  C:\\path\\file.js
      - Glob pattern:   /path/to/js/*.js
      - Burp XML:       burp_export.xml  (requires burp_mode=True)
      - view-source:    view-source:https://example.com/app.js

    Returns:
        - list of URL strings, OR
        - list of {'js': <content>, 'url': <url>} dicts (Burp mode)
    """
    if burp_mode:
        return _parse_burp_file(raw_input)

    # 1. Check if it's a local file FIRST (to avoid mistaking file.js for domain)
    # But only if it doesn't already have a scheme
    if not raw_input.startswith(SCHEMES):
        abs_path = os.path.abspath(raw_input)
        if os.path.isfile(abs_path):
            return [f"file://{abs_path}"]

    # 2. Normalize: handle view-source + bare domains/IPs
    raw_input = normalize_input(raw_input, scheme=scheme)

    # Strip trailing slash (but not from file://)
    if raw_input.endswith("/") and not raw_input.startswith("file://"):
        raw_input = raw_input.rstrip("/")

    # 3. Direct URL (scheme already present after normalize)
    if raw_input.startswith(SCHEMES):
        return [raw_input]

    # 4. Glob pattern (e.g. /path/to/js/*.js or C:\\js\\*.js)
    if "*" in raw_input:
        paths = glob.glob(os.path.abspath(raw_input))
        if not paths:
            raise ValueError(
                f"Glob pattern matched no files: {raw_input!r}\n"
                "  Tip: use quotes around glob patterns on some shells."
            )
        return [f"file://{p}" for p in paths]

    raise ValueError(
        f"Cannot resolve input: {raw_input!r}\n"
        "  Accepted formats:\n"
        "    URL        : https://example.com/app.js\n"
        "    Domain     : example.com  (auto-prepends https://)\n"
        "    Local file : /path/to/file.js\n"
        "    Glob       : /path/to/js/*.js\n"
        "    Burp XML   : burp.xml  (add --burp flag)"
    )


def _parse_burp_file(path: str) -> List[dict]:
    """Parse a Burp Suite XML export and extract JS responses."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Burp file not found: {path}")

    try:
        tree = ET.fromstring(open(path, "r", encoding="utf-8", errors="replace").read())
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Burp XML: {exc}") from exc

    results = []
    for item in tree:
        try:
            url_el      = item.find("url")
            response_el = item.find("response")
            if url_el is None or response_el is None:
                continue
            url = url_el.text or ""
            js  = base64.b64decode(response_el.text or "").decode("utf-8", "replace")
            results.append({"js": js, "url": url})
        except Exception as exc:
            logger.warning("Skipping Burp item: %s", exc)

    if not results:
        raise ValueError("No valid items found in Burp XML file.")
    return results


def extract_js_urls(
    html_content: str,
    base_url: str,
    ignore: str = "",
    only: str = "",
) -> List[str]:
    """
    Extract all <script src="..."> URLs from an HTML page.
    Resolves relative URLs against base_url.
    Supports ignore/only filtering.
    """
    parsed = urlparse(base_url)
    root   = f"{parsed.scheme}://{parsed.netloc}"
    path   = f"{parsed.scheme}://{parsed.netloc}/{parsed.path.lstrip('/')}"

    try:
        doc = lhtml.fromstring(html_content)
    except Exception as exc:
        logger.warning("lxml parse failed: %s", exc)
        return []

    all_src: List[str] = []
    for script in doc.xpath("//script"):
        src_list = script.xpath("@src")
        if not src_list:
            continue
        src = src_list[0]
        if src.startswith(("http://", "https://", "ftp://", "ftps://")):
            resolved = src
        elif src.startswith("//"):
            resolved = "http:" + src
        elif src.startswith("/"):
            resolved = root + src
        else:
            resolved = path + src

        if resolved not in all_src:
            all_src.append(resolved)

    # Apply ignore filter
    if ignore:
        ignore_terms = [t.strip() for t in ignore.split(";") if t.strip()]
        all_src = [s for s in all_src if not any(t in s for t in ignore_terms)]

    # Apply only filter
    if only:
        only_terms = [t.strip() for t in only.split(";") if t.strip()]
        all_src = [s for s in all_src if any(t in s for t in only_terms)]

    logger.info("Extracted %d JS URLs from %s", len(all_src), base_url)
    return all_src
