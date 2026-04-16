"""
Rule-Based Anomaly Detection Engine

AI DOCUMENTATION:
-----------------
This module implements the STATISTICAL / RULE-BASED layer of our hybrid
anomaly detection system. It does NOT call any external AI API.

HOW IT WORKS:
Each "rule" examines the parsed log entries and flags entries that deviate
from expected behavior. Rules produce anomalies with:
  - The flagged entry (or entries)
  - A human-readable reason
  - A confidence score (0.0 – 1.0) based on how extreme the deviation is

RULES IMPLEMENTED:
1. High Request Rate   – Single IP makes too many requests in a short window
2. Off-Hours Activity  – Requests outside normal business hours (06:00–22:00)
3. Large Data Transfer – Unusually large bytes sent or received
4. Blocked Actions     – Entries where the proxy blocked the request
5. Suspicious Status   – HTTP 4xx/5xx error spikes from one source
6. Suspicious Domains  – Access to domains with known-risky TLDs or patterns
7. Credential Stuffing – Multiple failed logins from the same IP
8. Slow Requests       – Abnormally long response times (possible exfiltration)

The module also computes summary statistics useful for the dashboard.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any
import statistics
import math


def analyze_logs(entries: List[Dict]) -> Dict[str, Any]:
    """
    Run all anomaly detection rules on the parsed log entries.

    Returns a dict with:
      - anomalies: list of flagged entries with reason + confidence
      - statistics: summary stats for the dashboard
      - timeline: bucketed event counts for timeline chart
    """
    if not entries:
        return {"anomalies": [], "statistics": {}, "timeline": []}

    anomalies = []
    anomalies += _rule_high_request_rate(entries)
    anomalies += _rule_off_hours(entries)
    anomalies += _rule_large_transfer(entries)
    anomalies += _rule_blocked_actions(entries)
    anomalies += _rule_suspicious_status(entries)
    anomalies += _rule_suspicious_domains(entries)
    anomalies += _rule_credential_stuffing(entries)
    anomalies += _rule_slow_requests(entries)

    # De-duplicate: same line_number can be flagged by multiple rules
    # Keep all reasons but merge into one entry
    merged = _merge_anomalies(anomalies)

    stats = _compute_statistics(entries, merged)
    timeline = _build_timeline(entries)

    return {
        "anomalies": merged,
        "statistics": stats,
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# Rule Implementations
# ---------------------------------------------------------------------------

def _rule_high_request_rate(entries: List[Dict], window_seconds=60, threshold=20) -> List[Dict]:
    """Flag IPs that make more than `threshold` requests within `window_seconds`."""
    anomalies = []
    by_ip = defaultdict(list)
    for e in entries:
        by_ip[e["source_ip"]].append(e)

    for ip, ip_entries in by_ip.items():
        sorted_entries = sorted(ip_entries, key=lambda x: x["timestamp"])
        window_start = 0
        for window_end in range(len(sorted_entries)):
            # Slide window
            while window_start < window_end:
                try:
                    t_start = datetime.fromisoformat(sorted_entries[window_start]["timestamp"].replace("Z", "+00:00"))
                    t_end = datetime.fromisoformat(sorted_entries[window_end]["timestamp"].replace("Z", "+00:00"))
                    if (t_end - t_start).total_seconds() <= window_seconds:
                        break
                except (ValueError, TypeError):
                    break
                window_start += 1

            count_in_window = window_end - window_start + 1
            if count_in_window >= threshold:
                confidence = min(1.0, 0.5 + (count_in_window - threshold) / (threshold * 2))
                anomalies.append({
                    "line_number": sorted_entries[window_end]["line_number"],
                    "entry": sorted_entries[window_end],
                    "rule": "high_request_rate",
                    "reason": f"High request rate: {count_in_window} requests from IP {ip} within {window_seconds}s window (threshold: {threshold})",
                    "confidence": round(confidence, 2),
                    "severity": "high" if confidence > 0.8 else "medium",
                })
                break  # One flag per IP is enough
    return anomalies


def _rule_off_hours(entries: List[Dict]) -> List[Dict]:
    """Flag requests made outside normal business hours (before 6 AM or after 10 PM)."""
    anomalies = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            hour = ts.hour
            if hour < 6 or hour >= 22:
                confidence = 0.4 if (hour >= 5 or hour <= 22) else 0.7
                if hour >= 0 and hour < 4:
                    confidence = 0.8
                anomalies.append({
                    "line_number": e["line_number"],
                    "entry": e,
                    "rule": "off_hours",
                    "reason": f"Off-hours activity: request at {ts.strftime('%H:%M')} UTC from user '{e.get('user', 'unknown')}'",
                    "confidence": round(confidence, 2),
                    "severity": "low" if confidence < 0.6 else "medium",
                })
        except (ValueError, TypeError):
            continue
    return anomalies


def _rule_large_transfer(entries: List[Dict], multiplier=5.0) -> List[Dict]:
    """Flag entries where bytes transferred is far above the median."""
    anomalies = []
    bytes_values = [e.get("bytes_received", 0) + e.get("bytes_sent", 0) for e in entries]
    if not bytes_values:
        return anomalies

    median_bytes = statistics.median(bytes_values)
    threshold = max(median_bytes * multiplier, 500_000)  # At least 500 KB

    for e in entries:
        total_bytes = e.get("bytes_received", 0) + e.get("bytes_sent", 0)
        if total_bytes > threshold and median_bytes > 0:
            ratio = total_bytes / median_bytes
            confidence = min(1.0, 0.5 + (ratio - multiplier) / (multiplier * 3))
            anomalies.append({
                "line_number": e["line_number"],
                "entry": e,
                "rule": "large_transfer",
                "reason": f"Large data transfer: {total_bytes:,} bytes ({ratio:.1f}x the median of {median_bytes:,.0f} bytes)",
                "confidence": round(max(confidence, 0.5), 2),
                "severity": "high" if total_bytes > 5_000_000 else "medium",
            })
    return anomalies


def _rule_blocked_actions(entries: List[Dict]) -> List[Dict]:
    """Flag entries where the proxy action was BLOCK or DENY."""
    anomalies = []
    for e in entries:
        action = e.get("action", "").upper()
        if action in ("BLOCK", "DENY", "DROP"):
            anomalies.append({
                "line_number": e["line_number"],
                "entry": e,
                "rule": "blocked_action",
                "reason": f"Blocked request: {action} action on {e.get('url', 'unknown URL')} — category: {e.get('category', 'unknown')}",
                "confidence": 0.6,
                "severity": "medium",
            })
    return anomalies


def _rule_suspicious_status(entries: List[Dict]) -> List[Dict]:
    """Flag IPs generating many 4xx or 5xx status codes."""
    anomalies = []
    error_counts = defaultdict(int)
    total_counts = defaultdict(int)

    for e in entries:
        ip = e["source_ip"]
        total_counts[ip] += 1
        code = e.get("status_code", 200)
        if code >= 400:
            error_counts[ip] += 1

    for ip, err_count in error_counts.items():
        total = total_counts[ip]
        error_rate = err_count / total if total > 0 else 0
        if err_count >= 5 and error_rate > 0.3:
            confidence = min(1.0, 0.4 + error_rate)
            # Flag the last error entry from this IP
            last_error = None
            for e in reversed(entries):
                if e["source_ip"] == ip and e.get("status_code", 200) >= 400:
                    last_error = e
                    break
            if last_error:
                anomalies.append({
                    "line_number": last_error["line_number"],
                    "entry": last_error,
                    "rule": "suspicious_status",
                    "reason": f"High error rate: IP {ip} has {err_count}/{total} requests with HTTP errors ({error_rate:.0%} error rate)",
                    "confidence": round(confidence, 2),
                    "severity": "high" if error_rate > 0.6 else "medium",
                })
    return anomalies


SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".zip", ".mov"}
SUSPICIOUS_PATTERNS = ["malware", "phishing", "c2", "botnet", "darkweb", "torrent", "hack"]


def _rule_suspicious_domains(entries: List[Dict]) -> List[Dict]:
    """Flag access to suspicious domains based on TLD and keyword patterns."""
    anomalies = []
    for e in entries:
        domain = e.get("domain", "")
        url = e.get("url", "").lower()
        reasons = []

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"suspicious TLD '{tld}'")
                break

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in url or pattern in domain:
                reasons.append(f"suspicious keyword '{pattern}'")
                break

        category = e.get("category", "").lower()
        if category in ("malware", "phishing", "command and control", "botnet", "anonymizer"):
            reasons.append(f"high-risk category '{e.get('category')}'")

        if reasons:
            confidence = min(1.0, 0.5 + 0.2 * len(reasons))
            anomalies.append({
                "line_number": e["line_number"],
                "entry": e,
                "rule": "suspicious_domain",
                "reason": f"Suspicious destination: {domain} — flagged for: {', '.join(reasons)}",
                "confidence": round(confidence, 2),
                "severity": "critical" if "malware" in " ".join(reasons) else "high",
            })
    return anomalies


LOGIN_PATH_MARKERS = ("/login", "/signin", "/auth", "/session", "/token")


def _rule_credential_stuffing(
    entries: List[Dict], window_seconds=120, threshold=5
) -> List[Dict]:
    """Flag repeated failed login attempts from a single IP in a short window."""
    anomalies = []
    by_ip = defaultdict(list)

    for e in entries:
        status = e.get("status_code", 200)
        method = e.get("method", "").upper()
        url = e.get("url", "").lower()
        is_login_attempt = any(marker in url for marker in LOGIN_PATH_MARKERS)

        if method == "POST" and status in (401, 403) and is_login_attempt:
            by_ip[e["source_ip"]].append(e)

    for ip, attempts in by_ip.items():
        sorted_attempts = sorted(attempts, key=lambda x: x["timestamp"])
        window_start = 0

        for window_end in range(len(sorted_attempts)):
            while window_start < window_end:
                try:
                    t_start = datetime.fromisoformat(
                        sorted_attempts[window_start]["timestamp"].replace("Z", "+00:00")
                    )
                    t_end = datetime.fromisoformat(
                        sorted_attempts[window_end]["timestamp"].replace("Z", "+00:00")
                    )
                    if (t_end - t_start).total_seconds() <= window_seconds:
                        break
                except (ValueError, TypeError):
                    break
                window_start += 1

            count_in_window = window_end - window_start + 1
            if count_in_window >= threshold:
                confidence = min(
                    1.0, 0.65 + (count_in_window - threshold) / max(threshold, 1)
                )
                last_attempt = sorted_attempts[window_end]
                anomalies.append(
                    {
                        "line_number": last_attempt["line_number"],
                        "entry": last_attempt,
                        "rule": "credential_stuffing",
                        "reason": (
                            f"Credential stuffing suspected: {count_in_window} failed login attempts "
                            f"from IP {ip} within {window_seconds}s"
                        ),
                        "confidence": round(confidence, 2),
                        "severity": "high" if count_in_window < threshold * 2 else "critical",
                    }
                )
                break

    return anomalies


def _rule_slow_requests(entries: List[Dict], multiplier=10.0) -> List[Dict]:
    """Flag abnormally slow requests (potential data exfiltration or tunneling)."""
    anomalies = []
    durations = [e.get("duration_ms", 0) for e in entries if e.get("duration_ms", 0) > 0]
    if not durations:
        return anomalies

    median_dur = statistics.median(durations)
    threshold = max(median_dur * multiplier, 10_000)  # At least 10 seconds

    for e in entries:
        dur = e.get("duration_ms", 0)
        if dur > threshold and median_dur > 0:
            ratio = dur / median_dur
            confidence = min(1.0, 0.4 + (ratio - multiplier) / (multiplier * 2))
            anomalies.append({
                "line_number": e["line_number"],
                "entry": e,
                "rule": "slow_request",
                "reason": f"Abnormally slow request: {dur:,}ms ({ratio:.1f}x the median of {median_dur:,.0f}ms) — possible tunneling or exfiltration",
                "confidence": round(max(confidence, 0.4), 2),
                "severity": "medium",
            })
    return anomalies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_anomalies(anomalies: List[Dict]) -> List[Dict]:
    """Merge anomalies that flag the same line into a single entry with multiple reasons."""
    by_line = defaultdict(list)
    for a in anomalies:
        by_line[a["line_number"]].append(a)

    merged = []
    for line_num, group in sorted(by_line.items()):
        if len(group) == 1:
            merged.append(group[0])
        else:
            best = max(group, key=lambda x: x["confidence"])
            all_reasons = [a["reason"] for a in group]
            all_rules = list(set(a["rule"] for a in group))
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            worst_severity = max(group, key=lambda x: severity_order.get(x["severity"], 0))["severity"]

            merged.append({
                "line_number": line_num,
                "entry": best["entry"],
                "rule": ", ".join(all_rules),
                "reason": " | ".join(all_reasons),
                "confidence": round(max(a["confidence"] for a in group), 2),
                "severity": worst_severity,
            })

    return sorted(merged, key=lambda x: x["confidence"], reverse=True)


def _compute_statistics(entries: List[Dict], anomalies: List[Dict]) -> Dict[str, Any]:
    """Compute summary statistics for the dashboard."""
    unique_ips = set(e["source_ip"] for e in entries)
    unique_users = set(e.get("user", "unknown") for e in entries)
    status_codes = Counter(e.get("status_code", 0) for e in entries)
    actions = Counter(e.get("action", "UNKNOWN").upper() for e in entries)
    categories = Counter(e.get("category", "Unknown") for e in entries)
    methods = Counter(e.get("method", "GET") for e in entries)
    top_domains = Counter(e.get("domain", "unknown") for e in entries).most_common(10)
    top_ips = Counter(e["source_ip"] for e in entries).most_common(10)

    severity_counts = Counter(a["severity"] for a in anomalies)

    bytes_total = sum(e.get("bytes_sent", 0) + e.get("bytes_received", 0) for e in entries)

    return {
        "total_entries": len(entries),
        "unique_ips": len(unique_ips),
        "unique_users": len(unique_users),
        "total_bytes": bytes_total,
        "status_codes": dict(status_codes),
        "actions": dict(actions),
        "categories": dict(categories.most_common(10)),
        "methods": dict(methods),
        "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "severity_breakdown": dict(severity_counts),
        "anomaly_count": len(anomalies),
    }


def _build_timeline(entries: List[Dict]) -> List[Dict]:
    """Bucket entries into time intervals for a timeline chart."""
    if not entries:
        return []

    buckets = defaultdict(lambda: {"total": 0, "errors": 0, "blocked": 0})

    for e in entries:
        try:
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            # Bucket by hour
            bucket_key = ts.strftime("%Y-%m-%dT%H:00:00Z")
            buckets[bucket_key]["total"] += 1
            if e.get("status_code", 200) >= 400:
                buckets[bucket_key]["errors"] += 1
            if e.get("action", "").upper() in ("BLOCK", "DENY", "DROP"):
                buckets[bucket_key]["blocked"] += 1
        except (ValueError, TypeError):
            continue

    return [
        {"time": k, **v}
        for k, v in sorted(buckets.items())
    ]
