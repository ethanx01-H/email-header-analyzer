"""
stix_export.py - Export IOCs and findings as STIX 2.1 bundles.
Enables sharing threat intelligence with SIEM/SOAR platforms.
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional


def generate_stix_bundle(headers: dict, iocs: dict, auth: dict, risk: dict,
                         enrichment: dict = None) -> dict:
    """Generate a STIX 2.1 bundle from email analysis."""
    objects = []

    # Identity (the analyzing organization)
    identity = {
        "type": "identity",
        "id": f"identity--{uuid.uuid4()}",
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": "Email Header Analysis Tool",
        "identity_class": "tool",
    }
    objects.append(identity)

    # Report (the analysis result)
    report = {
        "type": "report",
        "id": f"report--{uuid.uuid4()}",
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": f"Email Analysis: {headers.get('subject', 'Unknown')}",
        "published": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "report_types": ["threat-report"],
        "created_by_ref": identity["id"],
        "object_refs": [],
    }

    # Add IP indicators
    for ip in iocs.get("public_ips", []):
        ip_obj = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"Malicious IP: {ip}",
            "description": f"IP address found in email headers",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
        }
        objects.append(ip_obj)
        report["object_refs"].append(ip_obj["id"])

    # Add domain indicators
    for domain in iocs.get("domains", []):
        domain_obj = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"Suspicious Domain: {domain}",
            "description": f"Domain found in email headers",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
        }
        objects.append(domain_obj)
        report["object_refs"].append(domain_obj["id"])

    # Add URL indicators
    for url in iocs.get("urls", []):
        url_obj = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"Phishing URL: {url[:80]}",
            "description": f"URL found in email body",
            "pattern": f"[url:value = '{url}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
        }
        objects.append(url_obj)
        report["object_refs"].append(url_obj["id"])

    # Add email address indicators
    for email_addr in iocs.get("emails", []):
        email_obj = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"Suspicious Email: {email_addr}",
            "description": f"Email address found in headers",
            "pattern": f"[email-addr:value = '{email_addr}']",
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "indicator_types": ["malicious-activity"],
            "created_by_ref": identity["id"],
        }
        objects.append(email_obj)
        report["object_refs"].append(email_obj["id"])

    # Add attachment indicators (with hashes)
    for att in headers.get("attachments", []):
        if att.get("sha256"):
            att_obj = {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "name": f"Suspicious Attachment: {att.get('filename', 'unknown')}",
                "description": f"Attachment found in email",
                "pattern": f"[file:hashes.'SHA-256' = '{att['sha256']}']",
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "indicator_types": ["malicious-activity"],
                "created_by_ref": identity["id"],
            }
            objects.append(att_obj)
            report["object_refs"].append(att_obj["id"])

    # Add attack pattern (MITRE ATT&CK)
    if risk.get("signals"):
        for signal in risk["signals"]:
            finding = signal.get("finding", "").lower()
            if "phishing" in finding or "spoof" in finding:
                attack_pattern = {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{uuid.uuid4()}",
                    "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "name": "Phishing",
                    "description": signal.get("detail", ""),
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1566",
                            "url": "https://attack.mitre.org/techniques/T1566/",
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "initial-access",
                        }
                    ],
                }
                objects.append(attack_pattern)
                report["object_refs"].append(attack_pattern["id"])
                break

    # Add enrichment results as threat intelligence
    if enrichment:
        for ip, sources in enrichment.get("ip_results", {}).items():
            for source_name, data in sources.items():
                if isinstance(data, dict) and "MALICIOUS" in data.get("status", ""):
                    threat_actor = {
                        "type": "threat-actor",
                        "id": f"threat-actor--{uuid.uuid4()}",
                        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "name": f"Threat Actor (via {source_name})",
                        "description": f"IP {ip} flagged as malicious by {source_name}",
                        "threat_actor_types": ["criminal"],
                        "created_by_ref": identity["id"],
                    }
                    objects.append(threat_actor)
                    report["object_refs"].append(threat_actor["id"])

    # Add the report itself
    objects.append(report)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def export_stix_bundle(stix_bundle: dict, output_path: str) -> str:
    """Export STIX bundle to JSON file."""
    with open(output_path, "w") as f:
        json.dump(stix_bundle, f, indent=2)
    return output_path


def generate_stix_summary(stix_bundle: dict) -> dict:
    """Generate a summary of the STIX bundle."""
    objects = stix_bundle.get("objects", [])
    summary = {
        "total_objects": len(objects),
        "indicators": 0,
        "attack_patterns": 0,
        "threat_actors": 0,
        "reports": 0,
        "indicator_types": {},
    }

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "indicator":
            summary["indicators"] += 1
            for itype in obj.get("indicator_types", []):
                summary["indicator_types"][itype] = summary["indicator_types"].get(itype, 0) + 1
        elif obj_type == "attack-pattern":
            summary["attack_patterns"] += 1
        elif obj_type == "threat-actor":
            summary["threat_actors"] += 1
        elif obj_type == "report":
            summary["reports"] += 1

    return summary
