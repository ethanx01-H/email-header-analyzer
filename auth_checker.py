"""
auth_checker.py - Analyze SPF, DKIM, and DMARC authentication results.
Parses Authentication-Results headers and Received-SPF headers.
"""

import re
from typing import Optional


def analyze_authentication(headers: dict) -> dict:
    """Analyze all email authentication mechanisms."""
    spf = check_spf(headers)
    dkim = check_dkim(headers)
    dmarc = check_dmarc(headers)
    arc = check_arc(headers)

    # Overall auth verdict
    results = [spf["result"], dkim["result"], dmarc["result"]]
    if all(r == "PASS" for r in results if r != "NOT FOUND"):
        overall = "PASS"
    elif any(r == "FAIL" for r in results):
        overall = "FAIL"
    elif any(r == "SOFTFAIL" for r in results):
        overall = "SOFTFAIL"
    elif all(r == "NOT FOUND" for r in results):
        overall = "NOT FOUND"
    else:
        overall = "MIXED"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "arc": arc,
        "overall": overall,
    }


def check_spf(headers: dict) -> dict:
    """Check SPF authentication result."""
    result = {
        "result": "NOT FOUND",
        "detail": "",
        "domain": "",
        "mechanism": "",
        "source": "",
    }

    # Check Received-SPF header first (most direct)
    received_spf = headers.get("received_spf", "")
    if received_spf:
        result["source"] = "Received-SPF"
        parsed = _parse_received_spf(received_spf)
        result.update(parsed)
        return result

    # Check Authentication-Results
    auth_results = _get_auth_results(headers)
    for ar in auth_results:
        spf_match = re.search(
            r'spf=(\w+)',
            ar, re.IGNORECASE
        )
        if spf_match:
            result["result"] = spf_match.group(1).upper()
            result["source"] = "Authentication-Results"
            # Extract domain
            dom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', ar, re.IGNORECASE)
            if dom_match:
                result["domain"] = dom_match.group(1)
            # Extract detail
            detail_match = re.search(r'spf=.*?\(([^)]+)\)', ar, re.IGNORECASE)
            if detail_match:
                result["detail"] = detail_match.group(1)
            break

    # Check X-Authentication-Results (some MTAs use this)
    x_auth = headers.get("x_authentication_results", "")
    if result["result"] == "NOT FOUND" and x_auth:
        spf_match = re.search(r'spf=(\w+)', x_auth, re.IGNORECASE)
        if spf_match:
            result["result"] = spf_match.group(1).upper()
            result["source"] = "X-Authentication-Results"

    return result


def check_dkim(headers: dict) -> dict:
    """Check DKIM authentication result."""
    result = {
        "result": "NOT FOUND",
        "detail": "",
        "domain": "",
        "selector": "",
        "source": "",
    }

    # Check DKIM-Signature header exists
    dkim_sig = headers.get("dkim_signature", "")
    if not dkim_sig and not headers.get("x_google_dkim_signature", ""):
        return result

    # Extract selector from DKIM-Signature
    if dkim_sig:
        sel_match = re.search(r's=([^\s;]+)', dkim_sig, re.IGNORECASE)
        if sel_match:
            result["selector"] = sel_match.group(1)
        dom_match = re.search(r'd=([^\s;]+)', dkim_sig, re.IGNORECASE)
        if dom_match:
            result["domain"] = dom_match.group(1)

    # Check Authentication-Results for DKIM verdict
    auth_results = _get_auth_results(headers)
    for ar in auth_results:
        dkim_match = re.search(r'dkim=(\w+)', ar, re.IGNORECASE)
        if dkim_match:
            result["result"] = dkim_match.group(1).upper()
            result["source"] = "Authentication-Results"
            # Extract domain from auth results
            dom_match = re.search(r'dkim\.header\.i=@?([^\s;]+)', ar, re.IGNORECASE)
            if dom_match:
                result["domain"] = dom_match.group(1)
            detail_match = re.search(r'dkim=.*?\(([^)]+)\)', ar, re.IGNORECASE)
            if detail_match:
                result["detail"] = detail_match.group(1)
            break

    # Fallback: if we have a DKIM-Signature but no verdict
    if result["result"] == "NOT FOUND" and dkim_sig:
        result["result"] = "PRESENT (no verifier result)"
        result["source"] = "DKIM-Signature header"

    return result


def check_dmarc(headers: dict) -> dict:
    """Check DMARC authentication result."""
    result = {
        "result": "NOT FOUND",
        "detail": "",
        "domain": "",
        "policy": "",
        "source": "",
    }

    auth_results = _get_auth_results(headers)
    for ar in auth_results:
        dmarc_match = re.search(r'dmarc=(\w+)', ar, re.IGNORECASE)
        if dmarc_match:
            result["result"] = dmarc_match.group(1).upper()
            result["source"] = "Authentication-Results"
            # Extract policy action
            action_match = re.search(r'action=([^\s;]+)', ar, re.IGNORECASE)
            if action_match:
                result["policy"] = action_match.group(1)
            # Extract header.from domain
            dom_match = re.search(r'header\.from=([^\s;]+)', ar, re.IGNORECASE)
            if dom_match:
                result["domain"] = dom_match.group(1)
            break

    return result


def check_arc(headers: dict) -> dict:
    """Check ARC (Authenticated Received Chain) results."""
    result = {
        "result": "NOT FOUND",
        "detail": "",
        "source": "",
    }

    arc_ar = headers.get("arc_authentication_results", "")
    if arc_ar:
        result["source"] = "ARC-Authentication-Results"
        result["detail"] = arc_ar[:200]
        # Check for i= (instance number)
        instance_match = re.search(r'i=(\d+)', arc_ar)
        if instance_match:
            result["instance"] = int(instance_match.group(1))

    return result


def _get_auth_results(headers: dict) -> list:
    """Collect all Authentication-Results header values."""
    results = []
    ar = headers.get("authentication_results", "")
    if ar:
        results.append(ar)
    x_ar = headers.get("x_authentication_results", "")
    if x_ar:
        results.append(x_ar)
    return results


def _parse_received_spf(raw: str) -> dict:
    """Parse Received-SPF header value."""
    result = {"result": "UNKNOWN", "detail": "", "domain": "", "mechanism": ""}

    # First word is typically the result
    parts = raw.strip().split(None, 1)
    if parts:
        result["result"] = parts[0].upper()

    # Extract client-ip
    ip_match = re.search(r'client-ip=([^\s;]+)', raw, re.IGNORECASE)
    if ip_match:
        result["detail"] = f"client-ip={ip_match.group(1)}"

    # Extract envelope-from
    env_match = re.search(r'envelope-from=([^\s;]+)', raw, re.IGNORECASE)
    if env_match:
        result["domain"] = env_match.group(1)

    return result


def get_auth_risk_indicators(auth: dict) -> list:
    """Return risk indicators based on authentication results."""
    indicators = []

    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})

    # SPF failures
    if spf.get("result") == "FAIL":
        indicators.append({
            "severity": "HIGH",
            "finding": "SPF FAIL",
            "detail": f"Domain: {spf.get('domain', 'unknown')} — sender IP not authorized",
        })
    elif spf.get("result") == "SOFTFAIL":
        indicators.append({
            "severity": "MEDIUM",
            "finding": "SPF SOFTFAIL",
            "detail": f"Domain: {spf.get('domain', 'unknown')} — sender IP not explicitly authorized",
        })
    elif spf.get("result") == "NONE":
        indicators.append({
            "severity": "MEDIUM",
            "finding": "SPF NONE",
            "detail": "No SPF record found for sender domain",
        })

    # DKIM failures
    if dkim.get("result") == "FAIL":
        indicators.append({
            "severity": "HIGH",
            "finding": "DKIM FAIL",
            "detail": f"Domain: {dkim.get('domain', 'unknown')} — signature verification failed",
        })
    elif dkim.get("result") == "NOT FOUND":
        indicators.append({
            "severity": "LOW",
            "finding": "DKIM NOT FOUND",
            "detail": "No DKIM signature present",
        })

    # DMARC failures
    if dmarc.get("result") == "FAIL":
        indicators.append({
            "severity": "HIGH",
            "finding": "DMARC FAIL",
            "detail": f"Domain: {dmarc.get('domain', 'unknown')} — policy: {dmarc.get('policy', 'unknown')}",
        })
    elif dmarc.get("result") == "NOT FOUND":
        indicators.append({
            "severity": "MEDIUM",
            "finding": "DMARC NOT FOUND",
            "detail": "No DMARC record found",
        })

    # All pass
    if (spf.get("result") == "PASS" and
        dkim.get("result") == "PASS" and
        dmarc.get("result") == "PASS"):
        indicators.append({
            "severity": "INFO",
            "finding": "All authentication passed",
            "detail": "SPF, DKIM, and DMARC all verified successfully",
        })

    return indicators
