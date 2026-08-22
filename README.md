# Email Header Analysis Tool

CLI tool for analyzing `.eml` files.

Parses email headers, extracts IOCs, checks SPF/DKIM/DMARC authentication,
traces delivery hops, and calculates a tiered risk score.

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Usage

```bash
# Full analysis (default)
python3 email_analyzer.py <file.eml>

# Machine-readable JSON output
python3 email_analyzer.py <file.eml> --json

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
```

## What It Analyzes

### Email Summary
- Subject, From, To, Cc, Reply-To, Date, Message-ID
- Return-Path, X-Mailer, User-Agent
- Domain mismatch detection (From vs Return-Path)
- Attachment listing with types and sizes

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
- Domain names
- Email addresses
- URLs (http/https)

### Risk Scoring
- **STRONG signals** (weight 20-30): SPF/DKIM/DMARC FAIL, domain mismatch, suspicious mailer
- **MODERATE signals** (weight 8-15): SOFTFAIL, missing records, Reply-To mismatch
- **WEAK signals** (weight 3-5): No DKIM signature, clock skew
- Risk levels: CRITICAL (60+), HIGH (40+), MEDIUM (20+), LOW (5+), BENIGN (<5)
- Confidence score based on authentication coverage

## File Structure

```
email_header_analysis/
├── email_analyzer.py   # Main CLI entry point
├── header_parser.py    # .eml parsing and header extraction
├── ioc_extractor.py    # IOC extraction (IPs, domains, URLs, emails)
├── auth_checker.py     # SPF/DKIM/DMARC/ARC analysis
├── hop_tracer.py       # Received header hop tracing
├── risk_scorer.py      # Tiered risk scoring engine
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
```
