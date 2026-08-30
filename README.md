# Email Header Analysis Tool

CLI tool for analyzing `.eml` files.

Parses email headers, extracts IOCs, checks SPF/DKIM/DMARC authentication,
traces delivery hops, calculates a tiered risk score, and enriches IOCs
with live threat intelligence.

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)
- `dig` command (for DNS lookups, usually pre-installed on Linux)

## Quick Start

```bash
# Full analysis (local parsing only)
python3 email_analyzer.py suspicious.eml

# Full analysis + live threat intel enrichment
python3 email_analyzer.py suspicious.eml --enrich

# Configure API keys first (one-time setup)
python3 email_analyzer.py --setup
```

## Usage

```bash
# Full analysis (default)
python3 email_analyzer.py <file.eml>

# Full analysis with live threat intel enrichment
python3 email_analyzer.py <file.eml> --enrich

# Machine-readable JSON output
python3 email_analyzer.py <file.eml> --json

# JSON with enrichment
python3 email_analyzer.py <file.eml> --json --enrich

# Quick IOC extraction only
python3 email_analyzer.py <file.eml> --ioc

# Authentication check only (SPF/DKIM/DMARC)
python3 email_analyzer.py <file.eml> --auth

# Delivery hop trace only
python3 email_analyzer.py <file.eml> --hops

# Dump raw headers
python3 email_analyzer.py <file.eml> --raw

# Save report to file
python3 email_analyzer.py <file.eml> --export report

# Disable colored output (for piping/logging)
python3 email_analyzer.py <file.eml> --no-color

# Configure API keys interactively
python3 email_analyzer.py --setup

# Batch process all .eml files in a directory
python3 email_analyzer.py --batch /path/to/eml/files

# Generate Sigma detection rules
python3 email_analyzer.py <file.eml> --sigma

# Export IOCs as STIX 2.1 bundle
python3 email_analyzer.py <file.eml> --stix output.stix.json

# Generate HTML report
python3 email_analyzer.py <file.eml> --html report.html

# Combine multiple exports
python3 email_analyzer.py <file.eml> --enrich --sigma --stix output.stix.json --html report.html
```

## API Key Setup

The `--enrich` flag queries live threat intelligence sources. Some require API keys (all free):

```bash
python3 email_analyzer.py --setup
```

| Service | What it checks | Free tier | Get key at |
|---------|---------------|-----------|------------|
| VirusTotal | IPs, domains, URLs, file hashes | 4 req/min, 500/day | [virustotal.com](https://www.virustotal.com/gui/my-api-key) |
| AbuseIPDB | IP reputation, abuse reports | 1000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| abuse.ch | URLhaus + ThreatFox IOCs | Free (fair use) | [auth.abuse.ch](https://auth.abuse.ch/) |

Keys can also be set via environment variables:

```bash
export VT_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
export ABUSECH_AUTH_KEY=your_key
```

Without API keys, `--enrich` still works for DNS lookups and reverse DNS (no key needed).

## What It Analyzes

### Email Summary
- Subject, From, To, Cc, Reply-To, Date, Message-ID
- Return-Path, X-Mailer, User-Agent
- Domain mismatch detection (From vs Return-Path)
- Attachment listing with types, sizes, and SHA256/MD5 hashes
- Forwarded email detection

### Authentication
- **SPF**: Parses Received-SPF and Authentication-Results headers
- **DKIM**: Checks DKIM-Signature presence and verifier results
- **DMARC**: Extracts policy and verdict from Authentication-Results
- **ARC**: Checks for ARC chain validation

### Delivery Path (Hop Trace)
- Parses all Received headers in chronological order
- Shows from→by for each hop with IP, protocol, and timestamp
- Calculates time deltas between hops
- Detects anomalies: clock skew, long delays, IP mismatches

### IOC Extraction
- Public and private IPv4/IPv6 addresses
- Domain names (broad TLD coverage)
- Email addresses
- URLs (http/https, including deobfuscated variants)
- Homoglyph/lookalike domain detection
- URL deobfuscation (hxxp, [.] notation, URL encoding)

### Risk Scoring
- **STRONG signals** (weight 20-30): SPF/DKIM/DMARC FAIL, domain mismatch, suspicious mailer, threat intel hits, homoglyph attacks
- **MODERATE signals** (weight 8-15): SOFTFAIL, missing records, Reply-To mismatch, no SPF in DNS, suspicious TLDs
- **WEAK signals** (weight 3-5): No DKIM signature, clock skew, forwarded emails
- Risk levels: CRITICAL (60+), HIGH (40+), MEDIUM (20+), LOW (5+), BENIGN (<5)
- Confidence score based on authentication coverage

### Threat Intel Enrichment (--enrich)
- **VirusTotal**: Detection ratio for IPs, domains, URLs
- **AbuseIPDB**: Abuse confidence score, country, ISP, report count
- **URLhaus**: Known malware URLs and hosts
- **ThreatFox**: C2 and malware IOC matches
- **DNS**: SPF/MX/TXT record verification, reverse DNS
- Tor exit node detection via reverse DNS
- **Parallel execution**: ThreadPoolExecutor for fast enrichment
- **Result caching**: 24-hour cache to avoid re-querying same IOCs

### Sigma Rule Generation (--sigma)
Generates Sigma detection rules from findings:
- Authentication failure rules
- Known malicious IP rules
- Phishing URL rules
- Suspicious X-Mailer rules
- Domain mismatch rules
- Homoglyph/lookalike domain rules
- Reply-To mismatch rules

### STIX 2.1 Export (--stix)
Exports IOCs as STIX 2.1 bundle for sharing with SIEM/SOAR:
- IP indicators
- Domain indicators
- URL indicators
- Email address indicators
- Attachment hash indicators
- MITRE ATT&CK attack patterns
- Threat actor information

### HTML Report (--html)
Generates professional HTML reports for sharing with stakeholders:
- Risk assessment with visual indicators
- Email summary
- Authentication results
- Delivery path visualization
- IOC listing
- Risk signals
- Threat intel enrichment results

### Batch Processing (--batch)
Process multiple .eml files at once:
```bash
python3 email_analyzer.py --batch /path/to/eml/files
python3 email_analyzer.py --batch /path/to/eml/files --export batch_results
```

## File Structure

```
email_header_analysis/
├── email_analyzer.py   # Main CLI entry point
├── header_parser.py    # .eml parsing and header extraction
├── ioc_extractor.py    # IOC extraction (IPs, domains, URLs, emails)
├── auth_checker.py     # SPF/DKIM/DMARC/ARC analysis
├── hop_tracer.py       # Received header hop tracing
├── risk_scorer.py      # Tiered risk scoring engine
├── threat_intel.py     # Live threat intel enrichment
├── sigma_generator.py  # Sigma rule generation
├── stix_export.py      # STIX 2.1 bundle export
├── html_report.py      # HTML report generation
├── config.py           # API key management
├── sample_phishing.eml # Sample phishing email for testing
├── requirements.txt
└── README.md
```

## JSON Output

Use `--json` for integration with SIEM, SOAR, or other tools:

```bash
python3 email_analyzer.py suspicious.eml --json | jq '.risk.level'
python3 email_analyzer.py suspicious.eml --json | jq '.iocs.public_ips'
python3 email_analyzer.py suspicious.eml --json | jq '.authentication.spf.result'
python3 email_analyzer.py suspicious.eml --json --enrich | jq '.enrichment.verdict'
```

## Examples

### Analyze a phishing email
```bash
python3 email_analyzer.py sample_phishing.eml
```

### Generate full report package
```bash
python3 email_analyzer.py suspicious.eml --enrich --sigma --stix iocs.stix.json --html report.html --export report
```

### Batch process and export results
```bash
python3 email_analyzer.py --batch ./suspect_emails --export batch_analysis
```

### Quick IOC extraction for SIEM ingestion
```bash
python3 email_analyzer.py suspicious.eml --json --enrich | jq '.iocs' > iocs.json
```
