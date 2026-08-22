"""
risk_scorer.py - Tiered risk scoring engine for email analysis.
SOC-grade scoring with STRONG/MODERATE/WEAK signal tiers.
"""

from typing import Optional


# Risk tiers
TIER_STRONG = "STRONG"    # Definitive indicators
TIER_MODERATE = "MODERATE"  # Suspicious but not conclusive
TIER_WEAK = "WEAK"        # Contextual signals

# Severity to score mapping
SEVERITY_SCORES = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}

# Risk level thresholds
THRESHOLDS = {
    "CRITICAL": 60,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 5,
}


def calculate_risk(auth: dict, iocs: dict, hops: dict, headers: dict, enrichment: dict = None) -> dict:
    """Calculate overall risk score from all analysis components, optionally including threat intel."""
    signals = []

    # --- Authentication signals ---
    spf_result = auth.get("spf", {}).get("result", "NOT FOUND")
    dkim_result = auth.get("dkim", {}).get("result", "NOT FOUND")
    dmarc_result = auth.get("dmarc", {}).get("result", "NOT FOUND")

    if spf_result == "FAIL":
        signals.append({
            "tier": TIER_STRONG,
            "severity": "HIGH",
            "score": 20,
            "finding": "SPF FAIL",
            "detail": "Sender IP not authorized by SPF record",
        })
    elif spf_result == "SOFTFAIL":
        signals.append({
            "tier": TIER_MODERATE,
            "severity": "MEDIUM",
            "score": 10,
            "finding": "SPF SOFTFAIL",
            "detail": "Sender IP not explicitly authorized",
        })
    elif spf_result == "NONE":
        signals.append({
            "tier": TIER_MODERATE,
            "severity": "MEDIUM",
            "score": 8,
            "finding": "SPF NONE",
            "detail": "No SPF record for sender domain",
        })

    if dkim_result == "FAIL":
        signals.append({
            "tier": TIER_STRONG,
            "severity": "HIGH",
            "score": 20,
            "finding": "DKIM FAIL",
            "detail": "DKIM signature verification failed",
        })
    elif dkim_result == "NOT FOUND":
        signals.append({
            "tier": TIER_WEAK,
            "severity": "LOW",
            "score": 3,
            "finding": "No DKIM signature",
            "detail": "Email lacks DKIM signing",
        })

    if dmarc_result == "FAIL":
        signals.append({
            "tier": TIER_STRONG,
            "severity": "HIGH",
            "score": 25,
            "finding": "DMARC FAIL",
            "detail": "DMARC policy check failed",
        })
    elif dmarc_result == "NOT FOUND":
        signals.append({
            "tier": TIER_MODERATE,
            "severity": "MEDIUM",
            "score": 8,
            "finding": "No DMARC",
            "detail": "Sender domain has no DMARC policy",
        })

    # --- IOC signals ---
    if iocs.get("domain_mismatch"):
        signals.append({
            "tier": TIER_STRONG,
            "severity": "HIGH",
            "score": 15,
            "finding": "Domain mismatch",
            "detail": f"From: {iocs.get('sender_domain')} vs Return-Path: {iocs.get('return_path_domain')}",
        })

    # --- Hop anomalies ---
    for anomaly in hops.get("anomalies", []):
        sev = anomaly.get("severity", "LOW")
        signals.append({
            "tier": TIER_MODERATE if sev in ("HIGH", "MEDIUM") else TIER_WEAK,
            "severity": sev,
            "score": SEVERITY_SCORES.get(sev, 5),
            "finding": anomaly.get("finding", ""),
            "detail": anomaly.get("detail", ""),
        })

    # --- Header anomaly signals ---
    from_parsed = headers.get("from_parsed", {})
    reply_to_parsed = headers.get("reply_to_parsed", {})

    if (from_parsed.get("address") and reply_to_parsed.get("address") and
            from_parsed["address"].split("@")[-1] != reply_to_parsed["address"].split("@")[-1]):
        signals.append({
            "tier": TIER_MODERATE,
            "severity": "MEDIUM",
            "score": 10,
            "finding": "Reply-To domain mismatch",
            "detail": f"From: {from_parsed['address']} vs Reply-To: {reply_to_parsed['address']}",
        })

    # Check for suspicious X-Mailer
    x_mailer = headers.get("x_mailer", "")
    if x_mailer:
        suspicious_mailers = ["PHPMailer", "King Phisher", "Gophish", "SET", "Social Engineer"]
        for sm in suspicious_mailers:
            if sm.lower() in x_mailer.lower():
                signals.append({
                    "tier": TIER_STRONG,
                    "severity": "CRITICAL",
                    "score": 30,
                    "finding": f"Suspicious mailer: {sm}",
                    "detail": f"X-Mailer: {x_mailer}",
                })

    # --- Threat intel enrichment signals ---
    if enrichment:
        from threat_intel import get_enrichment_risk_signals
        enrichment_signals = get_enrichment_risk_signals(enrichment)
        signals.extend(enrichment_signals)

    # --- Calculate total ---
    total_score = sum(s["score"] for s in signals)

    # Determine risk level
    risk_level = "BENIGN"
    for level, threshold in sorted(THRESHOLDS.items(), key=lambda x: -x[1]):
        if total_score >= threshold:
            risk_level = level
            break

    # Confidence based on coverage
    auth_checks = sum(1 for r in [spf_result, dkim_result, dmarc_result] if r != "NOT FOUND")
    confidence = (auth_checks / 3) * 100

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "signals": signals,
        "signal_count": len(signals),
        "strong_signals": [s for s in signals if s["tier"] == TIER_STRONG],
        "moderate_signals": [s for s in signals if s["tier"] == TIER_MODERATE],
        "weak_signals": [s for s in signals if s["tier"] == TIER_WEAK],
    }
