"""
ioc_extractor.py - Extract Indicators of Compromise from email headers.
IPs, domains, URLs, email addresses, suspicious patterns.
"""

import re
from typing import Set


# Regex patterns
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# IPv6 (simplified)
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:com|net|org|io|co|info|biz|xyz|top|club|online|site|tech|'
    r'store|app|dev|cloud|me|us|uk|de|fr|ru|cn|br|in|au|jp|kr|sg|'
    r'mm|my|th|vn|ph|id|kh|la|bd|pk|lk|np|tw|hk|mo)\b'
)

EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Private/reserved IP ranges
PRIVATE_IP_RANGES = [
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
    (0xA9FE0000, 0xA9FEFFFF),  # 169.254.0.0/16
]


def extract_all_iocs(headers: dict) -> dict:
    """Extract all IOCs from parsed email headers."""
    # Combine all text sources for extraction
    text_sources = []
    for key in ["raw_headers", "body_preview"]:
        val = headers.get(key, "")
        if val:
            text_sources.append(val)

    # Also include specific header values
    for key in ["x_originating_ip", "authentication_results",
                 "x_authentication_results", "received_spf",
                 "dkim_signature", "received"]:
        val = headers.get(key, "")
        if isinstance(val, list):
            text_sources.extend(val)
        elif val:
            text_sources.append(val)

    full_text = "\n".join(text_sources)

    ips = extract_ips(full_text)
    domains = extract_domains(full_text)
    emails = extract_emails(full_text)
    urls = extract_urls(full_text)

    # Classify IPs
    public_ips = []
    private_ips = []
    for ip in ips:
        if _is_private_ip(ip):
            private_ips.append(ip)
        else:
            public_ips.append(ip)

    # Extract sender domain
    sender_domain = ""
    from_parsed = headers.get("from_parsed", {})
    if from_parsed.get("address"):
        parts = from_parsed["address"].split("@")
        if len(parts) == 2:
            sender_domain = parts[1]

    # Extract return-path domain
    return_path_domain = ""
    rp_parsed = headers.get("return_path_parsed", {})
    if rp_parsed.get("address"):
        parts = rp_parsed["address"].split("@")
        if len(parts) == 2:
            return_path_domain = parts[1]

    return {
        "ips": sorted(ips),
        "public_ips": sorted(public_ips),
        "private_ips": sorted(private_ips),
        "domains": sorted(domains),
        "emails": sorted(emails),
        "urls": sorted(urls),
        "sender_domain": sender_domain,
        "return_path_domain": return_path_domain,
        "domain_mismatch": sender_domain != return_path_domain and return_path_domain != "",
    }


def extract_ips(text: str) -> Set[str]:
    """Extract IPv4 and IPv6 addresses from text."""
    ips = set()
    for match in IP_PATTERN.finditer(text):
        ip = match.group()
        # Exclude obviously non-IP patterns
        parts = ip.split(".")
        if len(parts) == 4:
            ips.add(ip)
    for match in IPV6_PATTERN.finditer(text):
        ips.add(match.group())
    return ips


def extract_domains(text: str) -> Set[str]:
    """Extract domain names from text."""
    domains = set()
    for match in DOMAIN_PATTERN.finditer(text):
        d = match.group().lower().rstrip(".")
        # Filter out common noise
        if d not in ("example.com", "localhost.localdomain"):
            domains.add(d)
    return domains


def extract_emails(text: str) -> Set[str]:
    """Extract email addresses from text."""
    emails = set()
    for match in EMAIL_PATTERN.finditer(text):
        emails.add(match.group().lower())
    return emails


def extract_urls(text: str) -> Set[str]:
    """Extract URLs from text."""
    urls = set()
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:!?)")
        urls.add(url)
    return urls


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        val = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        for start, end in PRIVATE_IP_RANGES:
            if start <= val <= end:
                return True
        return False
    except (ValueError, IndexError):
        return False
