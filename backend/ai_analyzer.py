"""
AI-Powered Log Analysis using Anthropic's Claude API

AI DOCUMENTATION:
-----------------
This module is the SECOND layer of our hybrid anomaly detection system.
It uses the Anthropic Claude API (LLM) to perform deeper contextual analysis
that rule-based systems cannot easily achieve.

HOW AI IS USED:
1. We take the parsed log entries and the rule-based analysis results
2. We construct a structured prompt that includes:
   - A sample of log entries (to stay within token limits)
   - The rule-based anomalies already detected
   - Summary statistics
3. We ask Claude to act as a SOC analyst and provide:
   - An executive summary of the security posture
   - A prioritized timeline of notable events
   - Patterns that the statistical rules might have missed
   - Recommended next steps for the SOC team

WHY HYBRID?
- Rule-based: Fast, deterministic, low cost, catches known patterns
- AI (Claude): Contextual understanding, catches novel patterns,
  provides human-readable narrative, correlates across multiple signals

The AI layer adds value by:
- Correlating multiple low-confidence rule-based alerts into a coherent attack narrative
- Identifying subtle patterns (e.g., slow data exfiltration across many sessions)
- Generating natural-language summaries suitable for incident reports
- Providing actionable recommendations specific to the observed threats
"""

import json
from typing import List, Dict, Any, Optional

# We use the requests library to call the API directly
# (avoids requiring the anthropic SDK for simplicity)
import requests

from config import ActiveConfig

ANTHROPIC_API_KEY = ActiveConfig.ANTHROPIC_API_KEY
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = ActiveConfig.AI_MODEL


def ai_analyze_logs(
    entries: List[Dict],
    rule_results: Dict[str, Any],
    max_sample_entries: int = 50,
) -> Optional[Dict[str, Any]]:
    """
    Use Claude AI to perform deep contextual analysis of the log data.

    Args:
        entries: All parsed log entries
        rule_results: Results from the rule-based analyzer
        max_sample_entries: Max entries to include in the prompt (token management)

    Returns:
        Dict with AI-generated analysis, or None if API is unavailable
    """
    if not ANTHROPIC_API_KEY:
        return {
            "available": False,
            "error": "ANTHROPIC_API_KEY not set",
            "suggestion": "Set the ANTHROPIC_API_KEY environment variable to enable AI-powered analysis. "
                          "Get a key at https://console.anthropic.com/",
            "fallback_summary": _generate_fallback_summary(entries, rule_results),
        }

    # Prepare data for the prompt
    sample = _select_representative_sample(entries, rule_results, max_sample_entries)
    stats = rule_results.get("statistics", {})
    anomalies = rule_results.get("anomalies", [])

    prompt = _build_analysis_prompt(sample, anomalies, stats)

    try:
        response = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": MODEL,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
                "system": (
                    "You are an expert SOC (Security Operations Center) analyst. "
                    "Analyze the provided web proxy log data and anomaly detection results. "
                    "Respond ONLY with a valid JSON object (no markdown, no code fences). "
                    "Be concise, actionable, and prioritize the most critical findings."
                ),
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

        # Extract the text content from Claude's response
        content = data.get("content", [])
        text = ""
        for block in content:
            if block.get("type") == "text":
                text += block.get("text", "")

        # Parse the JSON response
        # Strip any potential markdown code fences
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        ai_result = json.loads(text)
        ai_result["available"] = True
        return ai_result

    except requests.exceptions.RequestException as e:
        return {
            "available": False,
            "error": f"API request failed: {str(e)}",
            "fallback_summary": _generate_fallback_summary(entries, rule_results),
        }
    except (json.JSONDecodeError, KeyError) as e:
        return {
            "available": False,
            "error": f"Failed to parse AI response: {str(e)}",
            "raw_response": text[:500] if 'text' in dir() else "No response",
            "fallback_summary": _generate_fallback_summary(entries, rule_results),
        }


def _select_representative_sample(
    entries: List[Dict], rule_results: Dict, max_count: int
) -> List[Dict]:
    """
    Select a representative sample of entries for the AI prompt.
    Prioritizes anomalous entries + a random sample of normal entries.
    """
    anomaly_lines = set(a["line_number"] for a in rule_results.get("anomalies", []))

    # Always include anomalous entries (up to half the budget)
    anomalous = [e for e in entries if e["line_number"] in anomaly_lines]
    anomalous = anomalous[: max_count // 2]

    # Fill remaining budget with evenly spaced normal entries
    normal = [e for e in entries if e["line_number"] not in anomaly_lines]
    remaining = max_count - len(anomalous)
    if remaining > 0 and normal:
        step = max(1, len(normal) // remaining)
        sampled_normal = normal[::step][:remaining]
    else:
        sampled_normal = []

    combined = anomalous + sampled_normal
    combined.sort(key=lambda x: x.get("timestamp", ""))

    # Slim down entries to reduce token usage
    slim = []
    for e in combined:
        slim.append({
            "timestamp": e.get("timestamp"),
            "source_ip": e.get("source_ip"),
            "user": e.get("user"),
            "method": e.get("method"),
            "url": e.get("url"),
            "status_code": e.get("status_code"),
            "action": e.get("action"),
            "category": e.get("category"),
            "bytes_sent": e.get("bytes_sent"),
            "bytes_received": e.get("bytes_received"),
            "duration_ms": e.get("duration_ms"),
        })
    return slim


def _build_analysis_prompt(
    sample_entries: List[Dict],
    anomalies: List[Dict],
    stats: Dict[str, Any],
) -> str:
    """Build the analysis prompt for Claude."""
    # Slim down anomalies for the prompt
    slim_anomalies = []
    for a in anomalies[:20]:  # Top 20 anomalies
        slim_anomalies.append({
            "rule": a["rule"],
            "reason": a["reason"],
            "confidence": a["confidence"],
            "severity": a["severity"],
            "source_ip": a["entry"].get("source_ip"),
            "timestamp": a["entry"].get("timestamp"),
        })

    return f"""Analyze these web proxy log entries and anomaly detection results.

## Summary Statistics
{json.dumps(stats, indent=2, default=str)}

## Rule-Based Anomalies Detected ({len(anomalies)} total)
{json.dumps(slim_anomalies, indent=2, default=str)}

## Sample Log Entries ({len(sample_entries)} of {stats.get('total_entries', '?')} total)
{json.dumps(sample_entries, indent=2, default=str)}

## Your Task
Respond with a JSON object containing:
{{
  "executive_summary": "2-3 sentence overview of the security posture",
  "threat_level": "critical|high|medium|low",
  "key_findings": [
    {{
      "title": "Finding title",
      "description": "What was found and why it matters",
      "severity": "critical|high|medium|low",
      "affected_entities": ["IPs or users involved"],
      "recommendation": "What the SOC team should do"
    }}
  ],
  "timeline": [
    {{
      "time": "timestamp or time range",
      "event": "What happened",
      "significance": "Why it matters"
    }}
  ],
  "patterns_detected": ["Patterns the rules may have missed"],
  "recommended_actions": ["Prioritized list of next steps"]
}}"""


def _generate_fallback_summary(entries: List[Dict], rule_results: Dict[str, Any]) -> Dict:
    """
    Generate a basic summary when the AI API is not available.
    This uses simple heuristics, not AI.
    """
    anomalies = rule_results.get("anomalies", [])
    stats = rule_results.get("statistics", {})

    severity_counts = stats.get("severity_breakdown", {})
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    if critical > 0:
        threat_level = "critical"
    elif high > 3:
        threat_level = "high"
    elif len(anomalies) > 5:
        threat_level = "medium"
    else:
        threat_level = "low"

    return {
        "executive_summary": (
            f"Analyzed {stats.get('total_entries', 0)} log entries from "
            f"{stats.get('unique_ips', 0)} unique IPs. "
            f"Found {len(anomalies)} anomalies "
            f"({critical} critical, {high} high severity). "
            f"AI-powered deep analysis is unavailable — set ANTHROPIC_API_KEY for enhanced insights."
        ),
        "threat_level": threat_level,
        "key_findings": [
            {
                "title": a["rule"],
                "description": a["reason"],
                "severity": a["severity"],
            }
            for a in anomalies[:5]
        ],
        "recommended_actions": [
            "Review all critical and high-severity anomalies",
            "Investigate IPs with high request rates for potential DDoS or scanning",
            "Check blocked requests for attempted policy violations",
            "Enable AI analysis (ANTHROPIC_API_KEY) for deeper threat correlation",
        ],
    }
