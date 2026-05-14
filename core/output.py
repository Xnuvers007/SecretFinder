#!/usr/bin/env python3
"""
SecretFinder - Output Formatters
Supports: CLI (colored), JSON, CSV, HTML (dark premium theme).
Rewritten & Enhanced by: https://github.com/Xnuvers007/SecretFinder
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime
from html import escape
from typing import List

from .patterns import Severity, SEVERITY_HTML_COLORS, SEVERITY_COLORS
from .scanner import ScanResult, Finding

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"


# ─── CLI Output ───────────────────────────────────────────────────────────────

def cli_output(results: List[ScanResult], use_color: bool = True) -> None:
    """Print findings to stdout with colored severity badges."""
    total = sum(len(r.findings) for r in results)
    if total == 0:
        _print(f"\n{DIM}[~] No secrets found.{RESET}", use_color)
        return

    for result in results:
        if not result.findings:
            continue
        _print(f"\n{BOLD}{CYAN}┌── {result.url}{RESET}", use_color)
        _print(f"{DIM}│   Scan time: {result.scan_duration_ms:.1f}ms{RESET}", use_color)

        for f in result.findings:
            color = SEVERITY_COLORS.get(f.severity, WHITE) if use_color else ""
            badge = f"[{f.severity.value}]"
            _print(
                f"{color}{BOLD}{badge:<12}{RESET} "
                f"{WHITE}{f.description:<40}{RESET}  "
                f"{DIM}{_truncate(f.matched, 80)}{RESET}",
                use_color,
            )

        _print(
            f"{DIM}└── {len(result.findings)} finding(s){RESET}",
            use_color,
        )

    # Footer Warning
    _print(f"\n{YELLOW}{BOLD}[!] WARNING:{RESET}{YELLOW} Results may contain false positives. Manual verification is advised.{RESET}", use_color)


def _print(msg: str, color: bool) -> None:
    if not color:
        # Strip ANSI codes
        import re
        msg = re.sub(r"\033\[[0-9;]*m", "", msg)
    print(msg)


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


# ─── JSON Output ──────────────────────────────────────────────────────────────

def json_output(results: List[ScanResult], path: str) -> None:
    """Write all results as a JSON file."""
    data = {
        "tool":      "SecretFinder",
        "author":    "Xnuvers007 (https://github.com/Xnuvers007/SecretFinder)",
        "original":  "m4ll0k (https://github.com/m4ll0k/SecretFinder)",
        "generated": datetime.utcnow().isoformat() + "Z",
        "results":   [r.to_dict() for r in results],
        "summary": {
            "total_files":    len(results),
            "total_findings": sum(len(r.findings) for r in results),
        },
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"[+] JSON saved → {os.path.abspath(path)}")


# ─── CSV Output ───────────────────────────────────────────────────────────────

def csv_output(results: List[ScanResult], path: str) -> None:
    """Write all findings as a flat CSV file."""
    fieldnames = [
        "source_url", "name", "description", "severity",
        "matched", "line_number", "context",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            for f in result.findings:
                writer.writerow({
                    "source_url":  f.source_url,
                    "name":        f.name,
                    "description": f.description,
                    "severity":    f.severity.value,
                    "matched":     f.matched,
                    "line_number": f.line_number,
                    "context":     f.context.replace("\n", " "),
                })
    print(f"[+] CSV  saved → {os.path.abspath(path)}")


# ─── HTML Output ─────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SecretFinder Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
  <style>
    :root {
      --bg:        #0d1117;
      --surface:   #161b22;
      --surface2:  #21262d;
      --border:    #30363d;
      --text:      #e6edf3;
      --muted:     #8b949e;
      --link:      #58a6ff;
      --crit:      #ff4d4d;
      --high:      #ff8c00;
      --medium:    #ffd700;
      --low:       #00bcd4;
      --info:      #6e7681;
      --green:     #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 24px;
    }
    /* ── Header ── */
    header {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 20px 24px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 24px;
    }
    header h1 {
      font-size: 22px;
      font-weight: 700;
      background: linear-gradient(135deg, #58a6ff, #bc8cff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    header .meta { margin-left: auto; color: var(--muted); font-size: 12px; text-align: right; }
    header .meta a { color: var(--link); text-decoration: none; }

    /* ── Summary cards ── */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
      text-align: center;
    }
    .card .count { font-size: 28px; font-weight: 700; }
    .card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; margin-top: 4px; }
    .card.total  .count { color: var(--text); }
    .card.crit   .count { color: var(--crit); }
    .card.high   .count { color: var(--high); }
    .card.medium .count { color: var(--medium); }
    .card.low    .count { color: var(--low); }
    .card.info   .count { color: var(--info); }

    /* ── File sections ── */
    .file-block {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 20px;
      overflow: hidden;
    }
    .file-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 20px;
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
    }
    .file-header a { color: var(--link); font-weight: 600; word-break: break-all; text-decoration: none; }
    .file-header a:hover { text-decoration: underline; }
    .file-header .badge {
      margin-left: auto;
      font-size: 11px;
      background: var(--border);
      border-radius: 20px;
      padding: 2px 10px;
      white-space: nowrap;
    }
    .file-scan-time { font-size: 11px; color: var(--muted); }

    /* ── Finding rows ── */
    .finding {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      display: grid;
      grid-template-columns: 100px 1fr;
      gap: 12px;
      align-items: start;
    }
    .finding:last-child { border-bottom: none; }
    .sev-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: .8px;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      width: 88px;
      text-align: center;
    }
    .sev-CRITICAL { background: rgba(255,77,77,.15);  color: var(--crit);   border: 1px solid var(--crit); }
    .sev-HIGH     { background: rgba(255,140,0,.15);  color: var(--high);   border: 1px solid var(--high); }
    .sev-MEDIUM   { background: rgba(255,215,0,.15);  color: var(--medium); border: 1px solid var(--medium); }
    .sev-LOW      { background: rgba(0,188,212,.15);  color: var(--low);    border: 1px solid var(--low); }
    .sev-INFO     { background: rgba(110,118,129,.15);color: var(--info);   border: 1px solid var(--info); }

    .finding-body .desc  { font-weight: 600; margin-bottom: 4px; }
    .finding-body .match {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      word-break: break-all;
      margin-bottom: 8px;
      color: #79c0ff;
    }
    .finding-body .context-label { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
    .finding-body .context {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      white-space: pre-wrap;
      word-break: break-all;
      color: var(--muted);
      max-height: 120px;
      overflow-y: auto;
    }
    .finding-body .line-no { font-size: 11px; color: var(--muted); margin-top: 4px; }
    .no-findings { padding: 20px; color: var(--muted); text-align: center; font-style: italic; }

    /* ── Footer ── */
    footer {
      margin-top: 32px;
      text-align: center;
      color: var(--muted);
      font-size: 12px;
    }
    footer a { color: var(--link); text-decoration: none; }
    footer a:hover { text-decoration: underline; }

    /* scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  </style>
</head>
<body>

<header>
  <div>
    <h1>🔍 SecretFinder Report</h1>
    <div style="font-size:12px;color:var(--muted);margin-top:4px;">
      Rewritten by <a href="https://github.com/Xnuvers007/SecretFinder" target="_blank" rel="noopener">Xnuvers007</a>
      &nbsp;·&nbsp;
      Based on <a href="https://github.com/m4ll0k/SecretFinder" target="_blank" rel="noopener">m4ll0k/SecretFinder</a>
    </div>
  </div>
  <div class="meta">
    Generated: $$GENERATED$$<br/>
    Files scanned: $$FILES$$
  </div>
</header>

<div style="background:rgba(255,215,0,0.1); border:1px solid var(--medium); border-radius:10px; padding:16px 20px; margin-bottom:24px; color:var(--medium); font-size:13px; display:flex; align-items:center; gap:12px;">
  <span style="font-size:20px;">⚠️</span>
  <div>
    <strong>False Positive Warning:</strong> 
    Some findings may be false positives (e.g. documentation links, generic UUIDs, or example strings). 
    A manual review is highly recommended before taking action.
  </div>
</div>

<div class="summary-grid">
  <div class="card total"> <div class="count">$$TOT$$</div> <div class="label">Total</div> </div>
  <div class="card crit">  <div class="count">$$CRIT$$</div><div class="label">Critical</div></div>
  <div class="card high">  <div class="count">$$HIGH$$</div><div class="label">High</div>    </div>
  <div class="card medium"><div class="count">$$MED$$</div> <div class="label">Medium</div>  </div>
  <div class="card low">   <div class="count">$$LOW$$</div> <div class="label">Low</div>     </div>
  <div class="card info">  <div class="count">$$INFO$$</div><div class="label">Info</div>    </div>
</div>

$$CONTENT$$

<footer>
  SecretFinder &nbsp;·&nbsp;
  <a href="https://github.com/Xnuvers007/SecretFinder" target="_blank" rel="noopener">github.com/Xnuvers007/SecretFinder</a>
  &nbsp;·&nbsp; Original by
  <a href="https://github.com/m4ll0k/SecretFinder" target="_blank" rel="noopener">m4ll0k</a>
</footer>
</body>
</html>
"""


def html_output(results: List[ScanResult], path: str) -> None:
    """Render a premium dark-mode HTML report and open in browser."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    total    = sum(len(r.findings) for r in results)
    critical = sum(len(r.critical) for r in results)
    high     = sum(len(r.high)     for r in results)
    medium   = sum(len(r.medium)   for r in results)
    low_cnt  = sum(len(r.low)      for r in results)
    info     = sum(len(r.info)     for r in results)

    content_parts: List[str] = []
    for result in results:
        file_block = _render_file_block(result)
        content_parts.append(file_block)

    html = (
        _HTML_TEMPLATE
        .replace("$$GENERATED$$", now)
        .replace("$$FILES$$",     str(len(results)))
        .replace("$$TOT$$",       str(total))
        .replace("$$CRIT$$",      str(critical))
        .replace("$$HIGH$$",      str(high))
        .replace("$$MED$$",       str(medium))
        .replace("$$LOW$$",       str(low_cnt))
        .replace("$$INFO$$",      str(info))
        .replace("$$CONTENT$$",   "\n".join(content_parts))
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

    abs_path = os.path.abspath(path)
    print(f"[+] HTML saved → {abs_path}")

    # Open in browser
    file_uri = f"file:///{abs_path.replace(os.sep, '/')}"
    try:
        import webbrowser, subprocess
        if sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", file_uri],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(file_uri)
    except Exception:
        pass


def _render_file_block(result: ScanResult) -> str:
    url_esc = escape(result.url)
    count   = len(result.findings)
    dur     = f"{result.scan_duration_ms:.1f}ms"

    rows: List[str] = []
    if not result.findings:
        rows.append('<div class="no-findings">No secrets found in this file.</div>')
    else:
        for f in result.findings:
            sev_cls   = f"sev-{f.severity.value}"
            ctx_esc   = escape(f.context)
            match_esc = escape(f.matched)
            desc_esc  = escape(f.description)
            line_info = f'<div class="line-no">Line {f.line_number}</div>' if f.line_number else ""
            rows.append(f"""
    <div class="finding">
      <div><span class="sev-badge {sev_cls}">{f.severity.value}</span></div>
      <div class="finding-body">
        <div class="desc">{desc_esc}</div>
        <div class="match">{match_esc}</div>
        <div class="context-label">Context:</div>
        <div class="context">{ctx_esc}</div>
        {line_info}
      </div>
    </div>""")

    error_banner = ""
    if result.error:
        error_banner = f'<div style="padding:10px 20px;color:#ff4d4d;font-size:12px;">⚠ {escape(result.error)}</div>'

    return f"""
<div class="file-block">
  <div class="file-header">
    <a href="{url_esc}" target="_blank" rel="noopener noreferrer">{url_esc}</a>
    <span class="file-scan-time">{dur}</span>
    <span class="badge">{count} finding{'s' if count != 1 else ''}</span>
  </div>
  {error_banner}
  {"".join(rows)}
</div>"""
