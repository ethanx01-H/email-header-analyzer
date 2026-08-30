"""
ioc_extractor.py - Extract Indicators of Compromise from email headers.
IPs, domains, URLs, email addresses, suspicious patterns.
"""

import re
import unicodedata
from typing import Set, List, Tuple


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
    r'[a-zA-Z]{2,}\b'
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

    # Homoglyph/lookalike domain analysis
    homoglyph_findings = analyze_sender_domain(headers)

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
        "homoglyph_findings": homoglyph_findings,
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
    """Extract URLs from text, including deobfuscated variants."""
    urls = set()

    # Standard URL extraction
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:!?)")
        urls.add(url)

    # Deobfuscate hxxp -> http
    deobfuscated = re.sub(r'hxxps?://', lambda m: 'https://' if 'hxxps' in m.group() else 'http://', text, flags=re.IGNORECASE)
    for match in URL_PATTERN.finditer(deobfuscated):
        url = match.group().rstrip(".,;:!?)")
        urls.add(url)

    # Deobfuscate [.] -> .
    deobfuscated2 = re.sub(r'\[\.\]', '.', text)
    for match in URL_PATTERN.finditer(deobfuscated2):
        url = match.group().rstrip(".,;:!?)")
        urls.add(url)

    # Deobfuscate URL encoding
    try:
        import urllib.parse
        decoded = urllib.parse.unquote(text)
        for match in URL_PATTERN.finditer(decoded):
            url = match.group().rstrip(".,;:!?)")
            urls.add(url)
    except Exception:
        pass

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


# ──────────────────────────────────────────────
#  HOMOGLYPH / LOOKALIKE DOMAIN DETECTION
# ──────────────────────────────────────────────

# Common homoglyph substitutions (Cyrillic, Greek, etc.)
HOMOGLYPH_MAP = {
    'a': ['а', 'ɑ', 'α'],  # Cyrillic а, Latin ɑ, Greek α
    'c': ['с', 'ϲ'],  # Cyrillic с, Greek ϲ
    'e': ['е', 'ε'],  # Cyrillic е, Greek ε
    'o': ['о', 'ο', '0'],  # Cyrillic о, Greek ο, zero
    'p': ['р', 'ρ'],  # Cyrillic р, Greek ρ
    'x': ['х', 'χ'],  # Cyrillic х, Greek χ
    'y': ['у', 'γ'],  # Cyrillic у, Greek γ
    'i': ['і', 'ι', '1', 'l', '1'],  # Ukrainian і, Greek ι, one, l
    'l': ['1', 'I', 'і'],  # one, capital I, Ukrainian і
    's': ['ѕ', 'ꜱ'],  # Cyrillic ѕ
    'n': ['ո', 'η'],  # Armenian ո, Greek η
    'd': ['ԁ', 'ɗ'],  # Cyrillic ԁ
    'g': ['ɡ', 'ǥ'],  # Latin ɡ
    'h': ['һ', 'ℎ'],  # Cyrillic һ
    'k': ['κ', 'ĸ'],  # Greek κ
    'm': ['ⅿ', 'rn'],  # Roman numeral, r+n combo
    'w': ['ѡ', 'ω'],  # Cyrillic ѡ, Greek ω
    '0': ['o', 'O', 'о'],  # zero -> o
    '1': ['l', 'I', 'і'],  # one -> l, I
}

# Common lookalike domain patterns (typosquatting)
LOOKALIKE_PATTERNS = [
    # Common brand typos
    (r'g[o0][o0]gle', 'google'),
    (r'micr[o0]s[o0]ft', 'microsoft'),
    (r'amaz[o0]n', 'amazon'),
    (r'payp[aа]l', 'paypal'),
    (r'apple\.c[o0]m', 'apple.com'),
    (r'faceb[o0][o0]k', 'facebook'),
    (r'netfl[i1]x', 'netflix'),
    (r'gma[i1]l', 'gmail'),
    (r'yah[o0][o0]', 'yahoo'),
    (r'outl[o0][o0]k', 'outlook'),
    (r'secure-c[o0]mpany', 'secure-company'),
]


def detect_homoglyphs(domain: str) -> List[dict]:
    """Detect homoglyph/lookalike domain attacks."""
    findings = []
    domain_lower = domain.lower()

    # Check for mixed-script characters
    has_cyrillic = any('Ѐ' <= c <= 'ӿ' for c in domain)
    has_greek = any('Ͱ' <= c <= 'Ͽ' for c in domain)
    has_latin = any('a' <= c <= 'z' for c in domain_lower)

    if (has_cyrillic or has_greek) and has_latin:
        findings.append({
            "type": "mixed_script",
            "severity": "CRITICAL",
            "detail": f"Mixed-script domain detected: {domain} (possible IDN homograph attack)",
        })

    # Check for numeric substitution (0 for o, 1 for l, etc.)
    numeric_substitutions = []
    for i, c in enumerate(domain_lower):
        if c in ('0', '1'):
            # Check if replacing with letter makes a known domain
            replacement = 'o' if c == '0' else 'l'
            test_domain = domain_lower[:i] + replacement + domain_lower[i+1:]
            # Check against common domains
            common_domains = ['google', 'microsoft', 'amazon', 'paypal', 'apple',
                            'facebook', 'netflix', 'gmail', 'yahoo', 'outlook',
                            'company', 'secure', 'bank', 'login', 'verify']
            for cd in common_domains:
                if cd in test_domain and cd not in domain_lower:
                    numeric_substitutions.append((i, c, replacement, cd))

    if numeric_substitutions:
        findings.append({
            "type": "numeric_substitution",
            "severity": "HIGH",
            "detail": f"Numeric substitution detected: {domain} (possible typosquatting)",
            "substitutions": numeric_substitutions,
        })

    # Check for lookalike patterns
    for pattern, target in LOOKALIKE_PATTERNS:
        if re.search(pattern, domain_lower):
            findings.append({
                "type": "lookalike_pattern",
                "severity": "HIGH",
                "detail": f"Lookalike pattern detected: {domain} resembles {target}",
            })

    # Check for suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.tech',
                       '.store', '.app', '.buzz', '.icu', '.cam', '.loan',
                       '.racing', '.review', '.stream', '.download', '.gdn',
                       '.men', '.party', '.science', '.trade', '.win',
                       '.bid', '.cc', '.ru', '.cn', '.su']
    for tld in suspicious_tlds:
        if domain_lower.endswith(tld):
            findings.append({
                "type": "suspicious_tld",
                "severity": "MEDIUM",
                "detail": f"Suspicious TLD: {tld} (commonly used in phishing)",
            })
            break

    return findings


def analyze_sender_domain(headers: dict) -> List[dict]:
    """Analyze sender domain for homoglyph/lookalike attacks."""
    findings = []

    from_parsed = headers.get("from_parsed", {})
    reply_to_parsed = headers.get("reply_to_parsed", {})
    return_path_parsed = headers.get("return_path_parsed", {})

    from_domain = from_parsed.get("address", "").split("@")[-1] if from_parsed.get("address") else ""
    reply_to_domain = reply_to_parsed.get("address", "").split("@")[-1] if reply_to_parsed.get("address") else ""
    return_path_domain = return_path_parsed.get("address", "").split("@")[-1] if return_path_parsed.get("address") else ""

    # Check From domain
    if from_domain:
        findings.extend(detect_homoglyphs(from_domain))

    # Check Reply-To domain
    if reply_to_domain and reply_to_domain != from_domain:
        findings.extend(detect_homoglyphs(reply_to_domain))

    # Check Return-Path domain
    if return_path_domain and return_path_domain != from_domain:
        findings.extend(detect_homoglyphs(return_path_domain))

    # Cross-domain comparison (From vs Reply-To)
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        # Check if they look similar (Levenshtein-like check)
        if _domains_look_similar(from_domain, reply_to_domain):
            findings.append({
                "type": "similar_reply_to",
                "severity": "HIGH",
                "detail": f"Reply-To domain '{reply_to_domain}' looks similar to From domain '{from_domain}'",
            })

    return findings


def _domains_look_similar(domain1: str, domain2: str) -> bool:
    """Check if two domains look suspiciously similar."""
    d1 = domain1.lower().split('.')[0]
    d2 = domain2.lower().split('.')[0]

    # Simple Levenshtein distance check
    if len(d1) < 3 or len(d2) < 3:
        return False

    # Check if one contains the other
    if d1 in d2 or d2 in d1:
        return True

    # Check character-by-character similarity
    if len(d1) == len(d2):
        diff_count = sum(1 for a, b in zip(d1, d2) if a != b)
        if diff_count <= 2:
            return True

    return False
