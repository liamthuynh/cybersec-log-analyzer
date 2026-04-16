"""
Log File Parser

Parses uploaded log files into structured dictionaries.

SUPPORTED FORMATS:
1. Web Proxy Logs (ZScaler-style) - our primary format
2. Apache/Nginx Combined Log Format
3. Generic CSV logs

Each parsed entry contains at minimum:
  - timestamp (ISO format string)
  - source_ip
  - raw_line (original log line)

Web proxy entries also include:
  - user, method, url, domain, status_code, bytes_sent,
    bytes_received, action, category, user_agent, duration_ms
"""

import re
import csv
import io
from datetime import datetime
from typing import List, Dict, Optional


def parse_log_file(filepath: str) -> List[Dict]:
    """
    Auto-detect log format and parse the file into structured entries.

    Args:
        filepath: Path to the log file on disk

    Returns:
        List of dictionaries, each representing one log entry
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if not lines:
        return []

    # Skip comment/header lines
    content_lines = [l for l in lines if l.strip() and not l.strip().startswith("#")]
    if not content_lines:
        return []

    # Try to detect format from first non-empty line
    first_line = content_lines[0].strip()

    # Check if it's CSV with a header row
    if "timestamp" in first_line.lower() and "," in first_line:
        return _parse_csv_logs(content_lines)

    # Check if it matches our web proxy log format
    if _is_proxy_log(first_line):
        return _parse_proxy_logs(content_lines)

    # Check for Apache/Nginx combined log format
    if _is_apache_log(first_line):
        return _parse_apache_logs(content_lines)

    # Fallback: try proxy format anyway (our sample files)
    return _parse_proxy_logs(content_lines)


# ---------------------------------------------------------------------------
# Web Proxy Log Parser (ZScaler-style)
# ---------------------------------------------------------------------------
# Format:
# 2025-01-15T08:23:45Z | 10.0.1.42 | jsmith | GET | https://example.com/path | 200 | 1523 | 45231 | ALLOW | Web Search | Mozilla/5.0 ... | 145

PROXY_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)\s*\|\s*"  # timestamp
    r"([\d.]+)\s*\|\s*"                                      # source_ip
    r"(\S+)\s*\|\s*"                                          # user
    r"(\S+)\s*\|\s*"                                          # method
    r"(\S+)\s*\|\s*"                                          # url
    r"(\d{3})\s*\|\s*"                                        # status_code
    r"(\d+)\s*\|\s*"                                          # bytes_sent
    r"(\d+)\s*\|\s*"                                          # bytes_received
    r"(\w+)\s*\|\s*"                                          # action
    r"([^|]+?)\s*\|\s*"                                       # category
    r"([^|]+?)\s*\|\s*"                                       # user_agent
    r"(\d+)\s*$"                                               # duration_ms
)


def _is_proxy_log(line: str) -> bool:
    return bool(PROXY_PATTERN.match(line.strip()))


def _parse_proxy_logs(lines: List[str]) -> List[Dict]:
    entries = []
    for i, line in enumerate(lines):
        line = line.strip()
        m = PROXY_PATTERN.match(line)
        if m:
            entries.append({
                "line_number": i + 1,
                "timestamp": m.group(1),
                "source_ip": m.group(2),
                "user": m.group(3),
                "method": m.group(4),
                "url": m.group(5),
                "domain": _extract_domain(m.group(5)),
                "status_code": int(m.group(6)),
                "bytes_sent": int(m.group(7)),
                "bytes_received": int(m.group(8)),
                "action": m.group(9),
                "category": m.group(10).strip(),
                "user_agent": m.group(11).strip(),
                "duration_ms": int(m.group(12)),
                "raw_line": line,
            })
    return entries


# ---------------------------------------------------------------------------
# Apache / Nginx Combined Log Format
# ---------------------------------------------------------------------------
# Format:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326

APACHE_PATTERN = re.compile(
    r'^([\d.]+)\s+'          # IP
    r'(\S+)\s+'               # ident
    r'(\S+)\s+'               # user
    r'\[([^\]]+)\]\s+'        # timestamp
    r'"(\S+)\s+(\S+)\s+\S+"\s+'  # method, url
    r'(\d{3})\s+'             # status
    r'(\d+|-)'                # bytes
)


def _is_apache_log(line: str) -> bool:
    return bool(APACHE_PATTERN.match(line.strip()))


def _parse_apache_logs(lines: List[str]) -> List[Dict]:
    entries = []
    for i, line in enumerate(lines):
        m = APACHE_PATTERN.match(line.strip())
        if m:
            ts_str = m.group(4)
            try:
                ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                ts_iso = ts.isoformat()
            except ValueError:
                ts_iso = ts_str

            entries.append({
                "line_number": i + 1,
                "timestamp": ts_iso,
                "source_ip": m.group(1),
                "user": m.group(3) if m.group(3) != "-" else "anonymous",
                "method": m.group(5),
                "url": m.group(6),
                "domain": _extract_domain(m.group(6)),
                "status_code": int(m.group(7)),
                "bytes_sent": int(m.group(8)) if m.group(8) != "-" else 0,
                "bytes_received": 0,
                "action": "ALLOW" if int(m.group(7)) < 400 else "BLOCK",
                "category": "Unknown",
                "user_agent": "Unknown",
                "duration_ms": 0,
                "raw_line": line.strip(),
            })
    return entries


# ---------------------------------------------------------------------------
# CSV Log Parser
# ---------------------------------------------------------------------------

def _parse_csv_logs(lines: List[str]) -> List[Dict]:
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    entries = []
    for i, row in enumerate(reader):
        entry = {
            "line_number": i + 2,  # +2 for header and 0-index
            "timestamp": row.get("timestamp", ""),
            "source_ip": row.get("source_ip", row.get("ip", "0.0.0.0")),
            "user": row.get("user", "unknown"),
            "method": row.get("method", "GET"),
            "url": row.get("url", ""),
            "domain": _extract_domain(row.get("url", "")),
            "status_code": int(row.get("status_code", row.get("status", 0))),
            "bytes_sent": int(row.get("bytes_sent", row.get("bytes", 0))),
            "bytes_received": int(row.get("bytes_received", 0)),
            "action": row.get("action", "ALLOW"),
            "category": row.get("category", "Unknown"),
            "user_agent": row.get("user_agent", "Unknown"),
            "duration_ms": int(row.get("duration_ms", row.get("duration", 0))),
            "raw_line": str(row),
        }
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract domain from a URL string."""
    if not url:
        return "unknown"
    url = url.lower()
    # Remove protocol
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    # Take the domain part
    domain = url.split("/")[0].split(":")[0]
    return domain or "unknown"
