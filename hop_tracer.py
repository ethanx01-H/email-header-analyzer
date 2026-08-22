"""
hop_tracer.py - Trace email delivery path from Received headers.
Builds a hop-by-hop timeline showing each MTA relay.
"""

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Optional


def trace_hops(headers: dict) -> dict:
    """Trace the full delivery path from Received headers."""
    received = headers.get("received", [])
    if not received:
        return {"hops": [], "hop_count": 0, "total_time_seconds": None, "anomalies": []}

    hops = []
    for i, recv in enumerate(received):
        hop = _parse_received_header(recv, i)
        hops.append(hop)

    # Received headers are in reverse order (newest first)
    hops.reverse()

    # Re-number after reversal
    for i, hop in enumerate(hops):
        hop["hop_number"] = i + 1

    # Calculate timing between hops
    _calculate_hop_timing(hops)

    # Detect anomalies
    anomalies = _detect_anomalies(hops, headers)

    total_time = None
    if hops and hops[0].get("timestamp") and hops[-1].get("timestamp"):
        try:
            t0 = _parse_timestamp(hops[0]["timestamp"])
            tN = _parse_timestamp(hops[-1]["timestamp"])
            if t0 and tN:
                total_time = abs((tN - t0).total_seconds())
        except Exception:
            pass

    return {
        "hops": hops,
        "hop_count": len(hops),
        "total_time_seconds": total_time,
        "anomalies": anomalies,
    }


def _parse_received_header(raw: str, index: int) -> dict:
    """Parse a single Received header into structured data."""
    hop = {
        "hop_number": index,
        "raw": raw.strip(),
        "from_host": "",
        "from_ip": "",
        "by_host": "",
        "with": "",
        "id": "",
        "for": "",
        "timestamp": "",
        "timestamp_parsed": None,
        "via": "",
    }

    # Extract "from" clause
    from_match = re.search(
        r'from\s+([^\s\(]+)(?:\s*\(([^\)]*)\))?',
        raw, re.IGNORECASE
    )
    if from_match:
        hop["from_host"] = from_match.group(1)
        # The parenthetical may contain IP, helo, etc.
        paren = from_match.group(2) or ""
        ip_match = re.search(r'\[([^\]]+)\]', paren)
        if ip_match:
            hop["from_ip"] = ip_match.group(1)

    # Extract "by" clause
    by_match = re.search(r'by\s+([^\s\(]+)', raw, re.IGNORECASE)
    if by_match:
        hop["by_host"] = by_match.group(1)

    # Extract "with" clause
    with_match = re.search(r'with\s+(\w+)', raw, re.IGNORECASE)
    if with_match:
        hop["with"] = with_match.group(1)

    # Extract "id" clause
    id_match = re.search(r'id\s+([^\s;]+)', raw, re.IGNORECASE)
    if id_match:
        hop["id"] = id_match.group(1)

    # Extract "for" clause
    for_match = re.search(r'for\s+([^\s;]+)', raw, re.IGNORECASE)
    if for_match:
        hop["for"] = for_match.group(1)

    # Extract "via" clause
    via_match = re.search(r'via\s+([^\s;]+)', raw, re.IGNORECASE)
    if via_match:
        hop["via"] = via_match.group(1)

    # Extract timestamp (usually at the end, after semicolon)
    ts_match = re.search(r';\s*(.+?)$', raw, re.IGNORECASE)
    if ts_match:
        ts_raw = ts_match.group(1).strip()
        hop["timestamp"] = ts_raw
        hop["timestamp_parsed"] = _parse_timestamp(ts_raw)

    return hop


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Try to parse a timestamp string."""
    try:
        return parsedate_to_datetime(ts_str)
    except Exception:
        pass

    # Try common formats
    formats = [
        "%d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _calculate_hop_timing(hops: list):
    """Calculate time delta between consecutive hops."""
    for i in range(len(hops)):
        hops[i]["time_delta_seconds"] = None
        hops[i]["time_delta_display"] = ""

        if i == 0:
            continue

        ts_prev = hops[i - 1].get("timestamp_parsed")
        ts_curr = hops[i].get("timestamp_parsed")

        if ts_prev and ts_curr:
            delta = (ts_curr - ts_prev).total_seconds()
            hops[i]["time_delta_seconds"] = delta
            hops[i]["time_delta_display"] = _format_duration(delta)


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 0:
        return f"({abs(seconds):.0f}s — clock skew)"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m}m"


def _detect_anomalies(hops: list, headers: dict) -> list:
    """Detect anomalies in the hop chain."""
    anomalies = []

    # Check for missing Received headers
    if len(hops) == 0:
        anomalies.append({
            "severity": "HIGH",
            "finding": "No Received headers found",
            "detail": "Cannot trace delivery path — headers may have been stripped",
        })
        return anomalies

    # Check for IP mismatches between hops
    for i in range(1, len(hops)):
        prev_by = hops[i - 1].get("from_host", "")
        curr_by = hops[i].get("by_host", "")
        # This is normal in many cases, but worth noting

    # Check for suspiciously long delays
    for hop in hops:
        delta = hop.get("time_delta_seconds")
        if delta and delta > 3600:  # > 1 hour
            anomalies.append({
                "severity": "MEDIUM",
                "finding": f"Long delay at hop {hop['hop_number']}",
                "detail": f"{hop['time_delta_display']} delay between hops",
            })

    # Check for clock skew (negative time deltas)
    for hop in hops:
        delta = hop.get("time_delta_seconds")
        if delta and delta < -60:  # More than 1 minute backwards
            anomalies.append({
                "severity": "LOW",
                "finding": f"Clock skew at hop {hop['hop_number']}",
                "detail": f"Timestamp went backwards by {abs(delta):.0f}s — MTA clock sync issue",
            })

    # Check if originating IP matches X-Originating-IP
    x_orig_ip = headers.get("x_originating_ip", "")
    if x_orig_ip:
        first_hop_ip = hops[0].get("from_ip", "") if hops else ""
        if first_hop_ip and x_orig_ip.strip("[]") != first_hop_ip:
            anomalies.append({
                "severity": "MEDIUM",
                "finding": "Originating IP mismatch",
                "detail": f"X-Originating-IP: {x_orig_ip} vs first hop: {first_hop_ip}",
            })

    # Check for internal relay count (excessive internal hops)
    internal_hops = sum(1 for h in hops if h.get("from_ip", "").startswith(("10.", "172.", "192.168.")))
    if internal_hops > 5:
        anomalies.append({
            "severity": "LOW",
            "finding": "Excessive internal relays",
            "detail": f"{internal_hops} internal hops detected — unusual for most organizations",
        })

    return anomalies
