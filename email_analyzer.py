#!/usr/bin/env python3
"""
email_analyzer.py - Email Header Analysis Tool
CLI tool for .eml analysis.

Parses .eml files, extracts IOCs, checks SPF/DKIM/DMARC,
traces delivery hops, and calculates risk scores.

Usage:
    python email_analyzer.py <file.eml>                 # Full analysis
    python email_analyzer.py <file.eml> --enrich         # Full + live threat intel
    python email_analyzer.py <file.eml> --json           # JSON output
    python email_analyzer.py <file.eml> --ioc            # IOCs only
    python email_analyzer.py <file.eml> --raw            # Raw headers only
    python email_analyzer.py <file.eml> --auth           # Auth check only
    python email_analyzer.py <file.eml> --hops           # Hop trace only
    python email_analyzer.py <file.eml> --export report  # Save report to file
    python email_analyzer.py --setup                     # Configure API keys
"""

import argparse
import json
import os
import sys
from datetime import datetime

# ANSI color codes
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    @staticmethod
    def disable():
        C.RESET = C.BOLD = C.DIM = ""
        C.RED = C.GREEN = C.YELLOW = C.BLUE = C.MAGENTA = C.CYAN = C.WHITE = ""
        C.BG_RED = C.BG_GREEN = C.BG_YELLOW = C.BG_BLUE = ""


def main():
    parser = argparse.ArgumentParser(
        description="Email Header Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.eml              Full analysis with risk score
  %(prog)s suspicious.eml --json       Machine-readable JSON output
  %(prog)s suspicious.eml --ioc        Extract IOCs only (fast)
  %(prog)s suspicious.eml --auth       SPF/DKIM/DMARC check only
  %(prog)s suspicious.eml --hops       Delivery path trace only
  %(prog)s suspicious.eml --raw        Dump raw headers
  %(prog)s suspicious.eml --export r   Save full report to .txt file
        """
    )
    parser.add_argument("eml_file", nargs="?", help="Path to .eml file to analyze")
    parser.add_argument("--enrich", action="store_true", help="Live threat intel enrichment (requires API keys)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--ioc", action="store_true", help="Extract IOCs only")
    parser.add_argument("--auth", action="store_true", help="Authentication check only")
    parser.add_argument("--hops", action="store_true", help="Hop trace only")
    parser.add_argument("--raw", action="store_true", help="Dump raw headers")
    parser.add_argument("--export", metavar="PREFIX", help="Save report to file (prefix)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--setup", action="store_true", help="Configure API keys interactively")

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    # Setup wizard
    if args.setup:
        from config import setup_wizard
        setup_wizard()
        return

    # Validate file
    if not args.eml_file:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.eml_file):
        print(f"{C.RED}[ERROR]{C.RESET} File not found: {args.eml_file}")
        sys.exit(1)

    if not args.eml_file.lower().endswith(".eml"):
        print(f"{C.YELLOW}[WARN]{C.RESET} File does not have .eml extension — attempting to parse anyway")

    # Import analysis modules
    try:
        from header_parser import parse_eml
        from ioc_extractor import extract_all_iocs
        from auth_checker import analyze_authentication, get_auth_risk_indicators
        from hop_tracer import trace_hops
        from risk_scorer import calculate_risk
    except ImportError as e:
        print(f"{C.RED}[ERROR]{C.RESET} Missing module: {e}")
        print("Make sure all .py files are in the same directory.")
        sys.exit(1)

    # Parse
    try:
        headers = parse_eml(args.eml_file)
    except Exception as e:
        print(f"{C.RED}[ERROR]{C.RESET} Failed to parse .eml: {e}")
        sys.exit(1)

    # Route to specific view or full analysis
    if args.json:
        _output_json(headers, args)
    elif args.ioc:
        _show_iocs(headers)
    elif args.auth:
        _show_auth(headers)
    elif args.hops:
        _show_hops(headers)
    elif args.raw:
        _show_raw(headers)
    else:
        _full_analysis(headers, args)


# ──────────────────────────────────────────────
#  FULL ANALYSIS
# ──────────────────────────────────────────────

def _full_analysis(headers: dict, args):
    from ioc_extractor import extract_all_iocs
    from auth_checker import analyze_authentication, get_auth_risk_indicators
    from hop_tracer import trace_hops
    from risk_scorer import calculate_risk

    iocs = extract_all_iocs(headers)
    auth = analyze_authentication(headers)
    hops = trace_hops(headers)

    # Enrichment (optional)
    enrichment = None
    if args.enrich:
        from threat_intel import enrich_iocs
        print(f"  {C.CYAN}[*] Running threat intel enrichment...{C.RESET}")
        enrichment = enrich_iocs(iocs)

    risk = calculate_risk(auth, iocs, hops, headers, enrichment)

    # Banner
    _print_banner()

    # Email summary
    _print_section("EMAIL SUMMARY")
    _print_field("Subject", headers.get("subject", "(empty)"))
    _print_field("From", headers.get("from", "(empty)"))
    _print_field("To", headers.get("to", "(empty)"))
    if headers.get("cc"):
        _print_field("Cc", headers["cc"])
    if headers.get("reply_to"):
        _print_field("Reply-To", headers["reply_to"])
    _print_field("Date", headers.get("date", "(empty)"))
    _print_field("Message-ID", headers.get("message_id", "(empty)"))
    if headers.get("return_path"):
        _print_field("Return-Path", headers["return_path"])
    if headers.get("x_mailer"):
        _print_field("X-Mailer", headers["x_mailer"])
    if headers.get("user_agent"):
        _print_field("User-Agent", headers["user_agent"])

    # Domain mismatch warning
    if iocs.get("domain_mismatch"):
        print()
        print(f"  {C.BG_RED}{C.WHITE}{C.BOLD} WARNING {C.RESET} {C.RED}Domain mismatch: "
              f"From domain ({iocs['sender_domain']}) != Return-Path ({iocs['return_path_domain']}){C.RESET}")

    # Attachments
    atts = headers.get("attachments", [])
    if atts:
        print()
        _print_field("Attachments", f"{len(atts)} file(s)")
        for att in atts:
            size_kb = att["size_bytes"] / 1024
            print(f"    {C.DIM}├─{C.RESET} {att['filename']} ({att['content_type']}, {size_kb:.1f} KB)")

    # Risk Score
    print()
    _print_section("RISK ASSESSMENT")
    _print_risk_score(risk)

    # Authentication
    print()
    _print_section("AUTHENTICATION (SPF / DKIM / DMARC)")
    _print_auth(auth)

    # Hop Trace
    print()
    _print_section("DELIVERY PATH (Hop Trace)")
    _print_hops(hops)

    # IOCs
    print()
    _print_section("INDICATORS OF COMPROMISE")
    _print_iocs(iocs)

    # Threat Intel Enrichment
    if enrichment:
        print()
        _print_section("THREAT INTEL ENRICHMENT")
        _print_enrichment(enrichment)

    # Signals detail
    if risk.get("signals"):
        print()
        _print_section("RISK SIGNALS")
        _print_signals(risk["signals"])

    # Footer
    print()
    _print_divider()
    print(f"  {C.DIM}Analysis complete — {risk['signal_count']} signal(s) detected{C.RESET}")
    print()

    # Export if requested
    if args.export:
        _export_report(headers, iocs, auth, hops, risk, args.export)


# ──────────────────────────────────────────────
#  SECTION PRINTERS
# ──────────────────────────────────────────────

def _print_banner():
    print()
    print(f"  {C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}║              EMAIL HEADER ANALYSIS TOOL                     ║{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}╚══════════════════════════════════════════════════════════════╝{C.RESET}")
    print()


def _print_section(title: str):
    print(f"  {C.BOLD}{C.BLUE}── {title} {'─' * max(0, 52 - len(title))}{C.RESET}")


def _print_divider():
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")


def _print_field(label: str, value: str, indent: int = 4):
    padded = f"{label}:".ljust(16)
    print(f"{' ' * indent}{C.DIM}{padded}{C.RESET} {value}")


def _print_risk_score(risk: dict):
    level = risk["risk_level"]
    score = risk["total_score"]
    confidence = risk["confidence"]

    # Color by risk level
    level_colors = {
        "CRITICAL": f"{C.BG_RED}{C.WHITE}{C.BOLD}",
        "HIGH": f"{C.RED}{C.BOLD}",
        "MEDIUM": f"{C.YELLOW}{C.BOLD}",
        "LOW": f"{C.CYAN}",
        "BENIGN": f"{C.GREEN}{C.BOLD}",
    }
    lc = level_colors.get(level, C.WHITE)

    # Score bar
    bar_len = min(score, 100)
    filled = "█" * (bar_len // 2)
    empty = "░" * (50 - bar_len // 2)

    if level in ("CRITICAL", "HIGH"):
        bar_color = C.RED
    elif level == "MEDIUM":
        bar_color = C.YELLOW
    else:
        bar_color = C.GREEN

    print(f"  {C.BOLD}Risk Level:{C.RESET}  {lc} {level} {C.RESET}")
    print(f"  {C.BOLD}Score:{C.RESET}       {score}/100  {bar_color}{filled}{empty}{C.RESET}")
    print(f"  {C.BOLD}Confidence:{C.RESET} {confidence:.0f}% (auth coverage)")
    print(f"  {C.BOLD}Signals:{C.RESET}     {len(risk.get('strong_signals', []))} strong, "
          f"{len(risk.get('moderate_signals', []))} moderate, "
          f"{len(risk.get('weak_signals', []))} weak")


def _print_auth(auth: dict):
    for mechanism in ["spf", "dkim", "dmarc"]:
        data = auth.get(mechanism, {})
        result = data.get("result", "NOT FOUND")
        label = mechanism.upper()

        # Color the result
        if result == "PASS":
            rc = f"{C.GREEN}✓ {result}{C.RESET}"
        elif result in ("FAIL", "HARDFAIL"):
            rc = f"{C.RED}✗ {result}{C.RESET}"
        elif result in ("SOFTFAIL", "NEUTRAL"):
            rc = f"{C.YELLOW}~ {result}{C.RESET}"
        elif "PRESENT" in result:
            rc = f"{C.YELLOW}◐ {result}{C.RESET}"
        else:
            rc = f"{C.DIM}○ {result}{C.RESET}"

        detail_parts = []
        if data.get("domain"):
            detail_parts.append(f"domain={data['domain']}")
        if data.get("selector"):
            detail_parts.append(f"s={data['selector']}")
        if data.get("policy"):
            detail_parts.append(f"policy={data['policy']}")
        if data.get("detail"):
            detail_parts.append(data["detail"])
        detail_str = "  ".join(detail_parts)

        print(f"    {C.BOLD}{label:>5}:{C.RESET} {rc}")
        if detail_str:
            print(f"           {C.DIM}{detail_str}{C.RESET}")

    # ARC
    arc = auth.get("arc", {})
    if arc.get("result") != "NOT FOUND":
        print(f"    {C.BOLD} ARC:{C.RESET} {C.CYAN}{arc.get('result', 'N/A')}{C.RESET}")

    # Overall
    overall = auth.get("overall", "UNKNOWN")
    oc = C.GREEN if overall == "PASS" else C.RED if overall == "FAIL" else C.YELLOW
    print(f"    {C.BOLD}  ──{C.RESET} Overall: {oc}{overall}{C.RESET}")


def _print_hops(hops: dict):
    hop_list = hops.get("hops", [])
    if not hop_list:
        print(f"    {C.DIM}No Received headers found — cannot trace delivery path{C.RESET}")
        return

    print(f"    {C.DIM}{hops['hop_count']} hop(s) | "
          f"Total transit: {_fmt_duration(hops.get('total_time_seconds'))}{C.RESET}")
    print()

    for hop in hop_list:
        num = hop["hop_number"]
        from_host = hop.get("from_host", "?")
        from_ip = hop.get("from_ip", "")
        by_host = hop.get("by_host", "?")
        proto = hop.get("with", "")
        ts = hop.get("timestamp", "")
        delta = hop.get("time_delta_display", "")

        # Arrow
        arrow = f"{C.CYAN}→{C.RESET}"

        # IP coloring (private = dim, public = normal)
        if from_ip:
            if _is_private(from_ip):
                ip_str = f"{C.DIM}[{from_ip}]{C.RESET}"
            else:
                ip_str = f"{C.YELLOW}[{from_ip}]{C.RESET}"
        else:
            ip_str = ""

        proto_str = f" {C.DIM}({proto}){C.RESET}" if proto else ""
        delta_str = f" {C.MAGENTA}+{delta}{C.RESET}" if delta else ""

        print(f"    {C.BOLD}[{num:>2}]{C.RESET} {from_host} {ip_str} {arrow} {by_host}{proto_str}{delta_str}")
        if ts:
            print(f"         {C.DIM}{ts}{C.RESET}")

    # Anomalies
    anomalies = hops.get("anomalies", [])
    if anomalies:
        print()
        for a in anomalies:
            sev = a.get("severity", "INFO")
            sc = _sev_color(sev)
            print(f"    {sc}[{sev}]{C.RESET} {a['finding']}: {C.DIM}{a['detail']}{C.RESET}")


def _print_iocs(iocs: dict):
    # Public IPs
    pub_ips = iocs.get("public_ips", [])
    if pub_ips:
        print(f"    {C.BOLD}Public IPs ({len(pub_ips)}):{C.RESET}")
        for ip in pub_ips:
            print(f"      {C.YELLOW}• {ip}{C.RESET}")

    # Private IPs
    priv_ips = iocs.get("private_ips", [])
    if priv_ips:
        print(f"    {C.BOLD}Private IPs ({len(priv_ips)}):{C.RESET}")
        for ip in priv_ips:
            print(f"      {C.DIM}• {ip}{C.RESET}")

    # Domains
    domains = iocs.get("domains", [])
    if domains:
        print(f"    {C.BOLD}Domains ({len(domains)}):{C.RESET}")
        for d in domains:
            # Highlight sender domain
            if d == iocs.get("sender_domain"):
                print(f"      {C.GREEN}• {d} (sender){C.RESET}")
            else:
                print(f"      {C.CYAN}• {d}{C.RESET}")

    # Emails
    emails = iocs.get("emails", [])
    if emails:
        print(f"    {C.BOLD}Email Addresses ({len(emails)}):{C.RESET}")
        for e in emails:
            print(f"      {C.MAGENTA}• {e}{C.RESET}")

    # URLs
    urls = iocs.get("urls", [])
    if urls:
        print(f"    {C.BOLD}URLs ({len(urls)}):{C.RESET}")
        for u in urls:
            print(f"      {C.RED}• {u}{C.RESET}")

    if not any([pub_ips, priv_ips, domains, emails, urls]):
        print(f"    {C.DIM}No IOCs extracted{C.RESET}")


def _print_enrichment(enrichment: dict):
    """Display threat intel enrichment results."""
    from threat_intel import get_enrichment_verdict
    verdict = get_enrichment_verdict(enrichment)
    summary = enrichment.get("summary", {})

    # Verdict banner
    vc = {
        "MALICIOUS": f"{C.BG_RED}{C.WHITE}{C.BOLD}",
        "LIKELY MALICIOUS": f"{C.RED}{C.BOLD}",
        "SUSPICIOUS": f"{C.YELLOW}{C.BOLD}",
        "POSSIBLY SUSPICIOUS": f"{C.YELLOW}",
        "CLEAN": f"{C.GREEN}{C.BOLD}",
        "UNKNOWN": f"{C.DIM}",
    }.get(verdict, C.WHITE)
    print(f"    Verdict: {vc} {verdict} {C.RESET}")
    print(f"    {C.DIM}Malicious: {summary.get('malicious', 0)}  "
          f"Suspicious: {summary.get('suspicious', 0)}  "
          f"Clean: {summary.get('clean', 0)}  "
          f"Unknown: {summary.get('unknown', 0)}  "
          f"Errors: {summary.get('errors', 0)}{C.RESET}")

    # IP results
    for ip, sources in enrichment.get("ip_results", {}).items():
        print(f"\n    {C.BOLD}IP: {ip}{C.RESET}")
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            _print_source_result(source_name, data)

    # Domain results
    for domain, sources in enrichment.get("domain_results", {}).items():
        print(f"\n    {C.BOLD}Domain: {domain}{C.RESET}")
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            _print_source_result(source_name, data)

    # URL results
    for url, sources in enrichment.get("url_results", {}).items():
        url_display = url[:70] + "..." if len(url) > 70 else url
        print(f"\n    {C.BOLD}URL: {url_display}{C.RESET}")
        for source_name, data in sources.items():
            if not isinstance(data, dict):
                continue
            _print_source_result(source_name, data)

    # ThreatFox
    tf_results = enrichment.get("threatfox", [])
    if tf_results:
        print(f"\n    {C.BOLD}ThreatFox Matches:{C.RESET}")
        for entry in tf_results:
            print(f"      {C.RED}• {entry.get('malware', 'unknown')}{C.RESET} — "
                  f"{entry.get('ioc', '')} ({entry.get('threat_type', '')})")

    # DNS results
    dns = enrichment.get("dns_results", {})
    if dns:
        print(f"\n    {C.BOLD}DNS Lookups:{C.RESET}")
        for domain, spf_data in dns.get("spf_records", {}).items():
            records = spf_data.get("records", [])
            if records:
                for r in records:
                    if "spf1" in r.lower():
                        print(f"      {C.GREEN}✓{C.RESET} SPF: {r[:80]}")
                    else:
                        print(f"      TXT: {r[:80]}")
            else:
                print(f"      {C.YELLOW}✗{C.RESET} No SPF record for {domain}")

        for domain, mx_data in dns.get("mx_records", {}).items():
            records = mx_data.get("records", [])
            if records:
                for r in records:
                    print(f"      MX: {r}")

        for ip, rdns in dns.get("reverse_dns", {}).items():
            hostname = rdns.get("hostname", "")
            if hostname:
                print(f"      {ip} → {hostname}")
            else:
                print(f"      {C.DIM}{ip} → (no rDNS){C.RESET}")


def _print_source_result(source_name: str, data: dict):
    """Print a single source result line."""
    status = data.get("status", "UNKNOWN")
    sc = {
        "MALICIOUS": C.RED,
        "SUSPICIOUS": C.YELLOW,
        "CLEAN": C.GREEN,
        "NOT FOUND": C.DIM,
        "ERROR": C.RED,
    }.get(status, C.DIM)

    # Build detail string
    details = []
    if data.get("detection_ratio"):
        details.append(f"detections: {data['detection_ratio']}")
    if data.get("abuse_confidence_score"):
        details.append(f"abuse: {data['abuse_confidence_score']}%")
    if data.get("total_reports"):
        details.append(f"reports: {data['total_reports']}")
    if data.get("country"):
        details.append(f"country: {data['country']}")
    if data.get("isp"):
        details.append(f"ISP: {data['isp']}")
    if data.get("threat"):
        details.append(f"threat: {data['threat']}")
    if data.get("hostname"):
        details.append(f"rDNS: {data['hostname']}")
    if data.get("error"):
        details.append(f"error: {data['error']}")

    detail_str = "  ".join(details) if details else ""
    icon = "✗" if "MALICIOUS" in status else "~" if "SUSPICIOUS" in status else "✓" if status == "CLEAN" else "○"

    print(f"      {sc}{icon} {source_name}: {status}{C.RESET}")
    if detail_str:
        print(f"        {C.DIM}{detail_str}{C.RESET}")


def _print_signals(signals: list):
    for s in signals:
        tier = s.get("tier", "")
        sev = s.get("severity", "")
        finding = s.get("finding", "")
        detail = s.get("detail", "")

        tc = {"STRONG": C.RED, "MODERATE": C.YELLOW, "WEAK": C.DIM}.get(tier, C.WHITE)
        sc = _sev_color(sev)

        print(f"    {tc}[{tier:>8}]{C.RESET} {sc}[{sev:>8}]{C.RESET} {finding}")
        if detail:
            print(f"    {C.DIM}{'':>19} {detail}{C.RESET}")


# ──────────────────────────────────────────────
#  SINGLE-VIEW MODES
# ──────────────────────────────────────────────

def _show_iocs(headers: dict):
    from ioc_extractor import extract_all_iocs
    iocs = extract_all_iocs(headers)
    _print_banner()
    _print_section("INDICATORS OF COMPROMISE")
    _print_iocs(iocs)
    print()


def _show_auth(headers: dict):
    from auth_checker import analyze_authentication
    auth = analyze_authentication(headers)
    _print_banner()
    _print_section("AUTHENTICATION (SPF / DKIM / DMARC)")
    _print_auth(auth)
    print()


def _show_hops(headers: dict):
    from hop_tracer import trace_hops
    hops = trace_hops(headers)
    _print_banner()
    _print_section("DELIVERY PATH (Hop Trace)")
    _print_hops(hops)
    print()


def _show_raw(headers: dict):
    _print_banner()
    _print_section("RAW HEADERS")
    print()
    print(headers.get("raw_headers", "(no headers)"))
    print()


def _output_json(headers: dict, args):
    from ioc_extractor import extract_all_iocs
    from auth_checker import analyze_authentication
    from hop_tracer import trace_hops
    from risk_scorer import calculate_risk

    iocs = extract_all_iocs(headers)
    auth = analyze_authentication(headers)
    hops = trace_hops(headers)

    # Enrichment (optional)
    enrichment = None
    if args.enrich:
        from threat_intel import enrich_iocs
        enrichment = enrich_iocs(iocs)

    risk = calculate_risk(auth, iocs, hops, headers, enrichment)

    # Remove non-serializable fields
    for hop in hops.get("hops", []):
        hop.pop("timestamp_parsed", None)
        hop.pop("time_delta_seconds", None)

    output = {
        "file": args.eml_file,
        "analyzed_at": datetime.now().isoformat(),
        "summary": {
            "subject": headers.get("subject", ""),
            "from": headers.get("from", ""),
            "to": headers.get("to", ""),
            "date": headers.get("date", ""),
            "message_id": headers.get("message_id", ""),
            "return_path": headers.get("return_path", ""),
        },
        "risk": {
            "level": risk["risk_level"],
            "score": risk["total_score"],
            "confidence": risk["confidence"],
            "signal_count": risk["signal_count"],
            "signals": risk["signals"],
        },
        "authentication": auth,
        "iocs": iocs,
        "hops": {
            "count": hops["hop_count"],
            "total_time_seconds": hops.get("total_time_seconds"),
            "anomalies": hops.get("anomalies", []),
            "path": hops.get("hops", []),
        },
        "attachments": headers.get("attachments", []),
    }

    if enrichment:
        from threat_intel import get_enrichment_verdict
        output["enrichment"] = enrichment
        output["enrichment"]["verdict"] = get_enrichment_verdict(enrichment)

    print(json.dumps(output, indent=2, default=str))


# ──────────────────────────────────────────────
#  EXPORT
# ──────────────────────────────────────────────

def _export_report(headers: dict, iocs: dict, auth: dict, hops: dict, risk: dict, prefix: str):
    """Save a plain-text report to file."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.txt"

    # Capture output by temporarily redirecting
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()

    C.disable()
    _print_banner()
    _print_section("EMAIL SUMMARY")
    _print_field("Subject", headers.get("subject", "(empty)"))
    _print_field("From", headers.get("from", "(empty)"))
    _print_field("To", headers.get("to", "(empty)"))
    _print_field("Date", headers.get("date", "(empty)"))
    _print_field("Message-ID", headers.get("message_id", "(empty)"))

    print()
    _print_section("RISK ASSESSMENT")
    _print_risk_score(risk)

    print()
    _print_section("AUTHENTICATION")
    _print_auth(auth)

    print()
    _print_section("DELIVERY PATH")
    _print_hops(hops)

    print()
    _print_section("IOCs")
    _print_iocs(iocs)

    if risk.get("signals"):
        print()
        _print_section("RISK SIGNALS")
        _print_signals(risk["signals"])

    sys.stdout = old_stdout
    # Restore colors by re-running the class definition values
    C.RESET = "\033[0m"; C.BOLD = "\033[1m"; C.DIM = "\033[2m"
    C.RED = "\033[91m"; C.GREEN = "\033[92m"; C.YELLOW = "\033[93m"
    C.BLUE = "\033[94m"; C.MAGENTA = "\033[95m"; C.CYAN = "\033[96m"
    C.WHITE = "\033[97m"
    C.BG_RED = "\033[41m"; C.BG_GREEN = "\033[42m"
    C.BG_YELLOW = "\033[43m"; C.BG_BLUE = "\033[44m"

    report = buffer.getvalue()
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"  {C.GREEN}✓{C.RESET} Report saved to: {C.BOLD}{filename}{C.RESET}")


# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────

def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": f"{C.BG_RED}{C.WHITE}",
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.CYAN,
        "INFO": C.DIM,
    }.get(sev, C.WHITE)


def _fmt_duration(seconds) -> str:
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


def _is_private(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 127:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 169 and b == 254:
            return True
        return False
    except (ValueError, IndexError):
        return False


if __name__ == "__main__":
    main()
