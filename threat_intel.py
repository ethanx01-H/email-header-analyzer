"""
threat_intel.py - Live IOC enrichment via threat intelligence APIs.
Queries VirusTotal, AbuseIPDB, URLhaus, ThreatFox, and DNS.

All functions are graceful — missing API keys return "NOT CONFIGURED",
network errors return "ERROR", never crash the tool.
"""

import hashlib
import json
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

from config import load_config


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def enrich_iocs(iocs: dict) -> dict:
    """Enrich all extracted IOCs with threat intelligence."""
    config = load_config()
    timeout = config.get("request_timeout", 10)
    max_per_source = config.get("max_iocs_per_source", 10)
    abusech_key = config.get("abusech_auth_key", "")

    results = {
        "ip_results": {},
        "domain_results": {},
        "url_results": {},
        "email_results": {},
        "dns_results": {},
        "summary": {
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "unknown": 0,
            "errors": 0,
        },
    }

    # --- DNS lookups (always available, no key needed) ---
    if config.get("dns_lookups_enabled", True):
        results["dns_results"] = _enrich_dns(iocs, timeout)

    # --- Enrich public IPs ---
    public_ips = iocs.get("public_ips", [])[:max_per_source]
    for ip in public_ips:
        ip_result = {}

        # VirusTotal
        if config.get("virustotal_api_key"):
            ip_result["virustotal"] = _vt_check_ip(ip, config["virustotal_api_key"], timeout)

        # AbuseIPDB
        if config.get("abuseipdb_api_key"):
            ip_result["abuseipdb"] = _abuseipdb_check_ip(ip, config["abuseipdb_api_key"], timeout)

        # Reverse DNS
        ip_result["reverse_dns"] = _reverse_dns(ip, timeout)

        results["ip_results"][ip] = ip_result
        _update_summary(results["summary"], ip_result)

    # --- Enrich domains ---
    domains = iocs.get("domains", [])[:max_per_source]
    for domain in domains:
        domain_result = {}

        if config.get("virustotal_api_key"):
            domain_result["virustotal"] = _vt_check_domain(domain, config["virustotal_api_key"], timeout)

        # URLhaus domain check
        if config.get("urlhaus_enabled", True) and abusech_key:
            domain_result["urlhaus"] = _urlhaus_check_host(domain, abusech_key, timeout)
        elif config.get("urlhaus_enabled", True):
            domain_result["urlhaus"] = {"source": "URLhaus", "status": "NOT CONFIGURED", "error": "No abuse.ch Auth-Key (get free at auth.abuse.ch)"}

        results["domain_results"][domain] = domain_result
        _update_summary(results["summary"], domain_result)

    # --- Enrich URLs ---
    urls = iocs.get("urls", [])[:max_per_source]
    for url in urls:
        url_result = {}

        if config.get("virustotal_api_key"):
            url_result["virustotal"] = _vt_check_url(url, config["virustotal_api_key"], timeout)

        # URLhaus URL check
        if config.get("urlhaus_enabled", True) and abusech_key:
            url_result["urlhaus"] = _urlhaus_check_url(url, abusech_key, timeout)
        elif config.get("urlhaus_enabled", True):
            url_result["urlhaus"] = {"source": "URLhaus", "status": "NOT CONFIGURED", "error": "No abuse.ch Auth-Key"}

        results["url_results"][url] = url_result
        _update_summary(results["summary"], url_result)

    # --- ThreatFox IOC check (bulk) ---
    if config.get("threatfox_enabled", True) and abusech_key:
        all_iocs_list = public_ips + domains
        if all_iocs_list:
            tf_results = _threatfox_bulk_check(all_iocs_list[:max_per_source], abusech_key, timeout)
            if tf_results:
                results["threatfox"] = tf_results
                for entry in tf_results:
                    if entry.get("malicious"):
                        results["summary"]["malicious"] += 1

    return results


# ──────────────────────────────────────────────
#  VIRUSTOTAL (v3 API)
# ──────────────────────────────────────────────

def _vt_check_ip(ip: str, api_key: str, timeout: int) -> dict:
    """Check IP on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    return _vt_query(url, api_key, timeout, "ip")


def _vt_check_domain(domain: str, api_key: str, timeout: int) -> dict:
    """Check domain on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    return _vt_query(url, api_key, timeout, "domain")


def _vt_check_url(url_to_check: str, api_key: str, timeout: int) -> dict:
    """Check URL on VirusTotal."""
    # VT requires URL ID as base64 of the URL
    import base64
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    return _vt_query(url, api_key, timeout, "url")


def _vt_check_hash(file_hash: str, api_key: str, timeout: int) -> dict:
    """Check file hash on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    return _vt_query(url, api_key, timeout, "file")


def _vt_query(url: str, api_key: str, timeout: int, ioc_type: str) -> dict:
    """Execute a VirusTotal v3 API query."""
    result = {
        "source": "VirusTotal",
        "status": "UNKNOWN",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "detection_ratio": "",
        "reputation": "",
        "tags": [],
        "error": "",
    }

    try:
        req = urllib.request.Request(url, headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        })
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result["malicious"] = stats.get("malicious", 0)
        result["suspicious"] = stats.get("suspicious", 0)
        result["harmless"] = stats.get("harmless", 0)
        result["undetected"] = stats.get("undetected", 0)
        result["total_engines"] = sum(stats.values())
        result["tags"] = attrs.get("tags", [])
        result["reputation"] = attrs.get("reputation", "")

        if result["total_engines"] > 0:
            result["detection_ratio"] = f"{result['malicious']}/{result['total_engines']}"

        if result["malicious"] >= 3:
            result["status"] = "MALICIOUS"
        elif result["malicious"] >= 1 or result["suspicious"] >= 3:
            result["status"] = "SUSPICIOUS"
        elif result["total_engines"] > 0:
            result["status"] = "CLEAN"
        else:
            result["status"] = "UNKNOWN"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["status"] = "NOT FOUND"
            result["error"] = "Not found in VT database"
        elif e.code == 401:
            result["status"] = "ERROR"
            result["error"] = "Invalid API key"
        elif e.code == 429:
            result["status"] = "ERROR"
            result["error"] = "Rate limited (try again later)"
        else:
            result["status"] = "ERROR"
            result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)[:100]

    return result


# ──────────────────────────────────────────────
#  ABUSEIPDB
# ──────────────────────────────────────────────

def _abuseipdb_check_ip(ip: str, api_key: str, timeout: int) -> dict:
    """Check IP on AbuseIPDB."""
    result = {
        "source": "AbuseIPDB",
        "status": "UNKNOWN",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country": "",
        "isp": "",
        "usage_type": "",
        "is_whitelisted": False,
        "last_reported": "",
        "error": "",
    }

    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        url = f"https://api.abuseipdb.com/api/v2/check?{params}"
        req = urllib.request.Request(url, headers={
            "Key": api_key,
            "Accept": "application/json",
        })
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)

        result["abuse_confidence_score"] = score
        result["total_reports"] = d.get("totalReports", 0)
        result["country"] = d.get("countryCode", "")
        result["isp"] = d.get("isp", "")
        result["usage_type"] = d.get("usageType", "")
        result["is_whitelisted"] = d.get("isWhitelisted", False)
        result["last_reported"] = d.get("lastReportedAt", "")

        if score >= 75:
            result["status"] = "MALICIOUS"
        elif score >= 25:
            result["status"] = "SUSPICIOUS"
        elif score >= 0:
            result["status"] = "CLEAN"

    except urllib.error.HTTPError as e:
        if e.code == 429:
            result["error"] = "Rate limited"
        elif e.code == 401:
            result["error"] = "Invalid API key"
        else:
            result["error"] = f"HTTP {e.code}"
        result["status"] = "ERROR"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["status"] = "ERROR"

    return result


# ──────────────────────────────────────────────
#  URLHAUS (requires abuse.ch Auth-Key)
# ──────────────────────────────────────────────

def _urlhaus_check_url(url: str, auth_key: str, timeout: int) -> dict:
    """Check URL against URLhaus."""
    result = {
        "source": "URLhaus",
        "status": "UNKNOWN",
        "threat": "",
        "tags": [],
        "date_added": "",
        "error": "",
    }

    try:
        post_data = urllib.parse.urlencode({"url": url}).encode()
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data=post_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Auth-Key": auth_key,
            },
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            result["status"] = "NOT FOUND"
            return result

        if query_status == "ok":
            result["threat"] = data.get("threat", "")
            result["tags"] = data.get("tags", [])
            result["date_added"] = data.get("date_added", "")

            url_status = data.get("url_status", "")
            if url_status in ("online", ""):
                result["status"] = "MALICIOUS"
            elif url_status == "offline":
                result["status"] = "MALICIOUS (offline)"
            else:
                result["status"] = "MALICIOUS"

    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            result["status"] = "ERROR"
            result["error"] = "Invalid or missing Auth-Key"
        else:
            result["error"] = f"HTTP {e.code}"
            result["status"] = "ERROR"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["status"] = "ERROR"

    return result


def _urlhaus_check_host(host: str, auth_key: str, timeout: int) -> dict:
    """Check host/domain against URLhaus."""
    result = {
        "source": "URLhaus",
        "status": "UNKNOWN",
        "url_count": 0,
        "urls": [],
        "error": "",
    }

    try:
        post_data = urllib.parse.urlencode({"host": host}).encode()
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=post_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Auth-Key": auth_key,
            },
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            result["status"] = "NOT FOUND"
            return result

        if query_status == "ok":
            urls = data.get("urls", [])
            result["url_count"] = data.get("urls_online", 0)
            result["urls"] = [u.get("url", "") for u in urls[:3]]

            if result["url_count"] > 0:
                result["status"] = "MALICIOUS"
            elif urls:
                result["status"] = "MALICIOUS (offline)"
            else:
                result["status"] = "NOT FOUND"

    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            result["status"] = "ERROR"
            result["error"] = "Invalid or missing Auth-Key"
        else:
            result["error"] = f"HTTP {e.code}"
            result["status"] = "ERROR"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["status"] = "ERROR"

    return result


# ──────────────────────────────────────────────
#  THREATFOX (requires abuse.ch Auth-Key)
# ──────────────────────────────────────────────

def _threatfox_bulk_check(iocs_list: list, auth_key: str, timeout: int) -> list:
    """Check IOCs against ThreatFox in bulk."""
    results = []

    try:
        post_data = json.dumps({
            "query": "search_ioc",
            "search_term": " ".join(iocs_list[:5]),
        }).encode()

        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=post_data,
            headers={
                "Content-Type": "application/json",
                "Auth-Key": auth_key,
            },
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        if data.get("query_status") == "ok":
            for ioc_entry in data.get("data", []):
                results.append({
                    "ioc": ioc_entry.get("ioc", ""),
                    "threat_type": ioc_entry.get("threat_type", ""),
                    "malware": ioc_entry.get("malware", ""),
                    "confidence": ioc_entry.get("confidence_level", 0),
                    "first_seen": ioc_entry.get("first_seen_utc", ""),
                    "last_seen": ioc_entry.get("last_seen_utc", ""),
                    "malicious": True,
                    "source": "ThreatFox",
                })

    except Exception:
        pass  # ThreatFox is optional, don't break on failure

    return results


# ──────────────────────────────────────────────
#  DNS LOOKUPS (stdlib only)
# ──────────────────────────────────────────────

def _enrich_dns(iocs: dict, timeout: int) -> dict:
    """Perform DNS lookups for domains and IPs."""
    dns_results = {
        "spf_records": {},
        "mx_records": {},
        "txt_records": {},
        "reverse_dns": {},
    }

    # Check SPF records for sender domain
    sender_domain = iocs.get("sender_domain", "")
    if sender_domain:
        dns_results["spf_records"][sender_domain] = _dns_query(sender_domain, "TXT", timeout)
        dns_results["mx_records"][sender_domain] = _dns_query(sender_domain, "MX", timeout)

    # Check return-path domain
    rp_domain = iocs.get("return_path_domain", "")
    if rp_domain and rp_domain != sender_domain:
        dns_results["spf_records"][rp_domain] = _dns_query(rp_domain, "TXT", timeout)
        dns_results["mx_records"][rp_domain] = _dns_query(rp_domain, "MX", timeout)

    # Reverse DNS for public IPs
    for ip in iocs.get("public_ips", []):
        dns_results["reverse_dns"][ip] = _reverse_dns(ip, timeout)

    return dns_results


def _dns_query(domain: str, record_type: str, timeout: int) -> dict:
    """Query DNS records using dig command (more reliable than stdlib for TXT/MX)."""
    result = {"records": [], "error": ""}

    try:
        import subprocess
        cmd = ["dig", "+short", "+timeout=5", domain, record_type]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0 and proc.stdout.strip():
            records = [line.strip().strip('"') for line in proc.stdout.strip().split("\n") if line.strip()]
            result["records"] = records
        elif proc.returncode != 0:
            # Fallback to socket
            if record_type == "MX":
                result["records"] = _socket_mx(domain)
            elif record_type == "TXT":
                result["records"] = _socket_txt(domain)
    except FileNotFoundError:
        # dig not available, use socket fallback
        if record_type == "MX":
            result["records"] = _socket_mx(domain)
        elif record_type == "TXT":
            result["records"] = _socket_txt(domain)
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def _socket_mx(domain: str) -> list:
    """Fallback MX lookup using socket."""
    try:
        import subprocess
        proc = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True, text=True, timeout=10)
        mx_records = []
        for line in proc.stdout.split("\n"):
            if "mail exchanger" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    mx_records.append(parts[-1].strip())
        return mx_records
    except Exception:
        return []


def _socket_txt(domain: str) -> list:
    """Fallback TXT lookup."""
    try:
        import subprocess
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=10)
        txt_records = []
        for line in proc.stdout.split("\n"):
            if "text" in line.lower() or "v=spf1" in line.lower():
                txt_records.append(line.strip())
        return txt_records
    except Exception:
        return []


def _reverse_dns(ip: str, timeout: int) -> dict:
    """Reverse DNS lookup for an IP."""
    result = {"hostname": "", "error": ""}
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["hostname"] = hostname
    except socket.herror:
        result["error"] = "No reverse DNS record"
    except socket.timeout:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────

def _update_summary(summary: dict, result: dict):
    """Update summary counts from a result dict."""
    for source_data in result.values():
        if isinstance(source_data, dict):
            status = source_data.get("status", "")
            if "MALICIOUS" in status:
                summary["malicious"] += 1
            elif "SUSPICIOUS" in status:
                summary["suspicious"] += 1
            elif status == "CLEAN":
                summary["clean"] += 1
            elif status == "ERROR":
                summary["errors"] += 1
            elif status in ("UNKNOWN", "NOT FOUND", "NOT CONFIGURED"):
                summary["unknown"] += 1


def get_enrichment_verdict(enrichment: dict) -> str:
    """Determine overall verdict from enrichment results."""
    summary = enrichment.get("summary", {})
    malicious = summary.get("malicious", 0)
    suspicious = summary.get("suspicious", 0)

    if malicious >= 2:
        return "MALICIOUS"
    elif malicious >= 1:
        return "LIKELY MALICIOUS"
    elif suspicious >= 2:
        return "SUSPICIOUS"
    elif suspicious >= 1:
        return "POSSIBLY SUSPICIOUS"
    elif summary.get("clean", 0) > 0 and malicious == 0 and suspicious == 0:
        return "CLEAN"
    else:
        return "UNKNOWN"


def get_enrichment_risk_signals(enrichment: dict) -> list:
    """Convert enrichment results into risk signals for the scorer."""
    signals = []

    # IP results
    for ip, sources in enrichment.get("ip_results", {}).items():
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            status = data.get("status", "")
            if "MALICIOUS" in status:
                score = 25
                if source_name == "virustotal":
                    ratio = data.get("detection_ratio", "")
                    detail = f"VT detection: {ratio}"
                    if data.get("malicious", 0) >= 10:
                        score = 30
                elif source_name == "abuseipdb":
                    abuse_score = data.get("abuse_confidence_score", 0)
                    detail = f"Abuse confidence: {abuse_score}%"
                    if abuse_score >= 90:
                        score = 30
                else:
                    detail = f"{source_name}: {status}"

                signals.append({
                    "tier": "STRONG",
                    "severity": "CRITICAL" if score >= 30 else "HIGH",
                    "score": score,
                    "finding": f"IP {ip} flagged by {source_name}",
                    "detail": detail,
                })
            elif "SUSPICIOUS" in status:
                signals.append({
                    "tier": "MODERATE",
                    "severity": "MEDIUM",
                    "score": 10,
                    "finding": f"IP {ip} suspicious on {source_name}",
                    "detail": f"Status: {status}",
                })

    # Domain results
    for domain, sources in enrichment.get("domain_results", {}).items():
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            status = data.get("status", "")
            if "MALICIOUS" in status:
                signals.append({
                    "tier": "STRONG",
                    "severity": "HIGH",
                    "score": 25,
                    "finding": f"Domain {domain} flagged by {source_name}",
                    "detail": f"Status: {status}",
                })

    # URL results
    for url, sources in enrichment.get("url_results", {}).items():
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            status = data.get("status", "")
            if "MALICIOUS" in status:
                signals.append({
                    "tier": "STRONG",
                    "severity": "CRITICAL",
                    "score": 30,
                    "finding": f"URL flagged by {source_name}",
                    "detail": f"URL: {url[:80]}",
                })

    # ThreatFox results
    for entry in enrichment.get("threatfox", []):
        if entry.get("malicious"):
            signals.append({
                "tier": "STRONG",
                "severity": "CRITICAL",
                "score": 30,
                "finding": f"ThreatFox match: {entry.get('malware', 'unknown')}",
                "detail": f"IOC: {entry.get('ioc', '')} | Type: {entry.get('threat_type', '')}",
            })

    # DNS anomalies
    dns = enrichment.get("dns_results", {})
    for domain, spf_data in dns.get("spf_records", {}).items():
        records = spf_data.get("records", [])
        if not records and not spf_data.get("error"):
            signals.append({
                "tier": "MODERATE",
                "severity": "MEDIUM",
                "score": 8,
                "finding": f"No SPF record for {domain}",
                "detail": "DNS TXT query returned no SPF record",
            })

    return signals
