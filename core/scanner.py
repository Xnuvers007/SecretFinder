#!/usr/bin/env python3
"""
SecretFinder - Core Scanner Engine
Handles regex matching, context extraction, deduplication, and result scoring.
Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import jsbeautifier

from .patterns import PATTERNS, Severity, SEVERITY_ORDER

logger = logging.getLogger("secretfinder.scanner")


@dataclass
class Finding:
    """Represents a single secret/pattern found during scanning."""
    name: str
    description: str
    severity: Severity
    matched: str
    context: str
    source_url: str
    line_number: Optional[int] = None
    char_offset: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "matched": self.matched,
            "context": self.context,
            "source_url": self.source_url,
            "line_number": self.line_number,
            "char_offset": self.char_offset,
        }


@dataclass
class ScanResult:
    """Aggregated results for one JS file/URL."""
    url: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    scan_duration_ms: float = 0.0

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def info(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.INFO]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "summary": {
                "total": len(self.findings),
                "critical": len(self.critical),
                "high": len(self.high),
                "medium": len(self.medium),
                "low": len(self.low),
                "info": len(self.info),
            }
        }


class SecretScanner:
    """
    Main scanning engine.
    Supports:
    - beautified JS parsing
    - raw fast mode (no beautifier)
    - custom regex injection
    - deduplication
    - severity sorting
    """

    CONTEXT_WINDOW = 120  # chars before/after match

    def __init__(
        self,
        extra_patterns: Optional[dict] = None,
        no_duplicates: bool = True,
        fast_mode: bool = False,
        severity_filter: Optional[List[Severity]] = None,
    ):
        self.patterns = dict(PATTERNS)
        if extra_patterns:
            for name, (pattern, sev, desc) in extra_patterns.items():
                self.patterns[name] = (pattern, sev, desc)
        self._compiled: dict[str, re.Pattern] = {}
        self._compile_patterns()
        self.no_duplicates = no_duplicates
        self.fast_mode = fast_mode
        self.severity_filter = set(severity_filter) if severity_filter else None

    def _compile_patterns(self) -> None:
        for name, (pattern, sev, desc) in self.patterns.items():
            try:
                self._compiled[name] = re.compile(
                    pattern, re.VERBOSE | re.IGNORECASE | re.MULTILINE
                )
            except re.error as exc:
                logger.warning("Invalid regex for '%s': %s", name, exc)

    def _beautify(self, content: str) -> str:
        """Beautify JS content for readability; fall back to simple split for large files."""
        if len(content) > 1_000_000:
            logger.debug("Large file — using fast split instead of jsbeautifier.")
            return content.replace(";", ";\n").replace(",", ",\n")
        try:
            return jsbeautifier.beautify(content)
        except Exception as exc:
            logger.warning("jsbeautifier failed: %s — using raw content.", exc)
            return content

    def _extract_context(self, content: str, match: re.Match) -> str:
        """Extract surrounding context for a regex match."""
        start = max(0, match.start() - self.CONTEXT_WINDOW)
        end   = min(len(content), match.end() + self.CONTEXT_WINDOW)
        return content[start:end].strip()

    def _get_line_number(self, content: str, offset: int) -> int:
        return content[:offset].count("\n") + 1

    def scan(self, content: str, source_url: str = "unknown") -> ScanResult:
        """
        Scan a JS content string and return a ScanResult.
        """
        import time
        t0 = time.perf_counter()

        result = ScanResult(url=source_url)
        seen_matches: set[str] = set()

        # Beautify unless fast mode
        if not self.fast_mode:
            content = self._beautify(content)

        for name, compiled in self._compiled.items():
            pattern_str, severity, description = self.patterns[name]

            # Apply severity filter if set
            if self.severity_filter and severity not in self.severity_filter:
                continue

            for m in compiled.finditer(content):
                matched_val = m.group(0).strip()

                if not matched_val:
                    continue

                # Deduplication: skip same match+type combo
                dedup_key = f"{name}::{matched_val}"
                if self.no_duplicates and dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                context = self._extract_context(content, m)
                line_no = self._get_line_number(content, m.start())

                finding = Finding(
                    name=name,
                    description=description,
                    severity=severity,
                    matched=matched_val,
                    context=context,
                    source_url=source_url,
                    line_number=line_no,
                    char_offset=m.start(),
                )
                result.findings.append(finding)

        # Sort by severity
        result.findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

        result.scan_duration_ms = (time.perf_counter() - t0) * 1000
        return result
