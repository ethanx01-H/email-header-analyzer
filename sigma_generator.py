"""
sigma_generator.py - Generate Sigma detection rules from email analysis findings.
Converts IOCs and risk signals into actionable detection content.
"""

import re
import yaml
from datetime import datetime
from typing import List, Dict, Optional


# MITRE ATT&CK mapping for email-based threats
ATTACK_MAPPING = {
    "phishing": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
        "sub_technique": "T1566.001 Spearphishing Attachment",
    },
    "phishing_link": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
        "sub_technique": "T1566.002 Spearphishing Link",
    },
    "credential_harvest": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
        "sub_technique": "T1566.002 Spearphishing Link",
    },
    "malware_delivery": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
        "sub_technique": "T1566.001 Spearphishing Attachment",
    },
    "suspicious_mailer": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
    },
    "auth_failure": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
    },
    "domain_spoof": {
        "tactic": "TA0001 Initial Access",
        "technique": "T1566 Phishing",
        "sub_technique": "T1566.001 Spearphishing Attachment",
    },
}


def generate_sigma_rules(headers: dict, iocs: dict, auth: dict, risk: dict) -> List[dict]:
    """Generate Sigma rules from email analysis findings."""
    rules = []

    # Rule 1: SPF/DKIM/DMARC failure from sender domain
    if auth.get("overall") == "FAIL":
        sender_domain = iocs.get("sender_domain", "")
        if sender_domain:
            rules.append(_generate_auth_failure_rule(sender_domain, auth))

    # Rule 2: Known malicious IP detection
    public_ips = iocs.get("public_ips", [])
    if public_ips:
        rules.append(_generate_malicious_ip_rule(public_ips))

    # Rule 3: Phishing URL detection
    urls = iocs.get("urls", [])
    if urls:
        rules.append(_generate_phishing_url_rule(urls))

    # Rule 4: Suspicious X-Mailer
    x_mailer = headers.get("x_mailer", "")
    if x_mailer:
        suspicious_mailers = ["PHPMailer", "King Phisher", "Gophish", "SET"]
        for sm in suspicious_mailers:
            if sm.lower() in x_mailer.lower():
                rules.append(_generate_suspicious_mailer_rule(x_mailer))
                break

    # Rule 5: Domain mismatch (From vs Return-Path)
    if iocs.get("domain_mismatch"):
        rules.append(_generate_domain_mismatch_rule(iocs))

    # Rule 6: Homoglyph/lookalike domain
    homoglyph_findings = iocs.get("homoglyph_findings", [])
    if homoglyph_findings:
        rules.append(_generate_homoglyph_rule(homoglyph_findings))

    # Rule 7: Reply-To mismatch
    from_parsed = headers.get("from_parsed", {})
    reply_to_parsed = headers.get("reply_to_parsed", {})
    if (from_parsed.get("address") and reply_to_parsed.get("address") and
            from_parsed["address"].split("@")[-1] != reply_to_parsed["address"].split("@")[-1]):
        rules.append(_generate_reply_to_mismatch_rule(from_parsed, reply_to_parsed))

    return rules


def _generate_auth_failure_rule(sender_domain: str, auth: dict) -> dict:
    """Generate rule for authentication failures."""
    conditions = []
    if auth.get("spf", {}).get("result") == "FAIL":
        conditions.append("SPF FAIL")
    if auth.get("dkim", {}).get("result") == "FAIL":
        conditions.append("DKIM FAIL")
    if auth.get("dmarc", {}).get("result") == "FAIL":
        conditions.append("DMARC FAIL")

    return {
        "title": f"Email Authentication Failure - {sender_domain}",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects email authentication failures ({', '.join(conditions)}) from {sender_domain}",
        "references": [
            "https://tools.ietf.org/html/rfc7208",
            "https://tools.ietf.org/html/rfc6376",
            "https://tools.ietf.org/html/rfc7489",
        ],
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566",
            "attack.t1566.001",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "sender_domain": sender_domain,
                "authentication_result": "fail",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate email forwarding",
            "Third-party email services",
        ],
        "level": "high",
    }


def _generate_malicious_ip_rule(ips: List[str]) -> dict:
    """Generate rule for known malicious IPs."""
    return {
        "title": "Email from Known Malicious IP",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects emails originating from known malicious IPs: {', '.join(ips[:3])}",
        "references": [
            "https://www.virustotal.com/",
            "https://www.abuseipdb.com/",
        ],
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "source_ip": ips,
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Compromised legitimate server",
        ],
        "level": "critical",
    }


def _generate_phishing_url_rule(urls: List[str]) -> dict:
    """Generate rule for phishing URLs."""
    return {
        "title": "Email Containing Phishing URL",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects emails containing known phishing URLs",
        "references": [
            "https://urlhaus.abuse.ch/",
        ],
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566.002",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "url|contains": [u[:100] for u in urls[:5]],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate URL that was compromised",
        ],
        "level": "high",
    }


def _generate_suspicious_mailer_rule(x_mailer: str) -> dict:
    """Generate rule for suspicious X-Mailer."""
    return {
        "title": f"Suspicious Email Client: {x_mailer}",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects emails sent using known phishing toolkit: {x_mailer}",
        "references": [
            "https://attack.mitre.org/techniques/T1566/",
        ],
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "x_mailer|contains": x_mailer,
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate use of PHPMailer",
        ],
        "level": "high",
    }


def _generate_domain_mismatch_rule(iocs: dict) -> dict:
    """Generate rule for domain mismatch."""
    return {
        "title": "Email Domain Mismatch (From vs Return-Path)",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects domain mismatch between From ({iocs.get('sender_domain')}) and Return-Path ({iocs.get('return_path_domain')})",
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "sender_domain": iocs.get("sender_domain", ""),
                "return_path_domain": iocs.get("return_path_domain", ""),
            },
            "filter": {
                "sender_domain": iocs.get("return_path_domain", ""),
            },
            "condition": "selection and not filter",
        },
        "falsepositives": [
            "Third-party email marketing services",
            "Email forwarding",
        ],
        "level": "medium",
    }


def _generate_homoglyph_rule(findings: List[dict]) -> dict:
    """Generate rule for homoglyph/lookalike domains."""
    return {
        "title": "Homoglyph/Lookalike Domain Attack",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": "Detects emails from homoglyph or lookalike domains (IDN homograph attack)",
        "references": [
            "https://attack.mitre.org/techniques/T1566/002/",
        ],
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566.002",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "sender_domain|re": r".*[0-9oO].*\.(com|net|org|io)",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate domains with numbers",
        ],
        "level": "high",
    }


def _generate_reply_to_mismatch_rule(from_parsed: dict, reply_to_parsed: dict) -> dict:
    """Generate rule for Reply-To mismatch."""
    return {
        "title": "Email Reply-To Domain Mismatch",
        "id": _generate_uuid(),
        "status": "experimental",
        "description": f"Detects Reply-To domain mismatch: From ({from_parsed.get('address')}) vs Reply-To ({reply_to_parsed.get('address')})",
        "author": "Email Header Analysis Tool",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.initial_access",
            "attack.t1566",
        ],
        "logsource": {
            "category": "email",
            "product": "exchange",
        },
        "detection": {
            "selection": {
                "from_domain": from_parsed.get("address", "").split("@")[-1],
                "reply_to_domain": reply_to_parsed.get("address", "").split("@")[-1],
            },
            "filter": {
                "from_domain": reply_to_parsed.get("address", "").split("@")[-1],
            },
            "condition": "selection and not filter",
        },
        "falsepositives": [
            "Third-party support systems",
        ],
        "level": "medium",
    }


def _generate_uuid() -> str:
    """Generate a simple UUID for Sigma rule ID."""
    import uuid
    return str(uuid.uuid4())


def export_sigma_rules(rules: List[dict], output_dir: str = ".") -> List[str]:
    """Export Sigma rules to YAML files."""
    import os
    exported = []

    for i, rule in enumerate(rules):
        # Sanitize filename (remove invalid characters)
        title = rule.get('title', 'unnamed')
        safe_title = re.sub(r'[^\w\s-]', '', title).strip().replace(' ', '_').lower()[:50]
        filename = f"sigma_rule_{i+1}_{safe_title}.yml"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            yaml.dump(rule, f, default_flow_style=False, sort_keys=False)

        exported.append(filepath)

    return exported


def get_mitre_attack_mapping(risk_signals: List[dict]) -> List[dict]:
    """Map risk signals to MITRE ATT&CK framework."""
    mappings = []

    for signal in risk_signals:
        finding = signal.get("finding", "").lower()

        if "spf" in finding or "dkim" in finding or "dmarc" in finding:
            mappings.append({
                "signal": signal.get("finding"),
                "tactic": "TA0001 Initial Access",
                "technique": "T1566 Phishing",
                "description": "Email authentication failure indicates potential spoofing",
            })
        elif "domain mismatch" in finding:
            mappings.append({
                "signal": signal.get("finding"),
                "tactic": "TA0001 Initial Access",
                "technique": "T1566 Phishing",
                "sub_technique": "T1566.001 Spearphishing Attachment",
                "description": "Domain mismatch indicates potential email spoofing",
            })
        elif "homoglyph" in finding or "lookalike" in finding:
            mappings.append({
                "signal": signal.get("finding"),
                "tactic": "TA0001 Initial Access",
                "technique": "T1566 Phishing",
                "sub_technique": "T1566.002 Spearphishing Link",
                "description": "Homoglyph domain indicates IDN homograph attack",
            })
        elif "suspicious mailer" in finding:
            mappings.append({
                "signal": signal.get("finding"),
                "tactic": "TA0001 Initial Access",
                "technique": "T1566 Phishing",
                "description": "Known phishing toolkit detected in X-Mailer",
            })
        elif "url" in finding.lower() or "phishing" in finding.lower():
            mappings.append({
                "signal": signal.get("finding"),
                "tactic": "TA0001 Initial Access",
                "technique": "T1566 Phishing",
                "sub_technique": "T1566.002 Spearphishing Link",
                "description": "Phishing URL detected in email",
            })

    return mappings
