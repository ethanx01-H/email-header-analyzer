"""
header_parser.py - Parse .eml files and extract all email headers.
Parse .eml files and extract all email headers.
"""

import email
import email.policy
import email.utils
import hashlib
from email.message import EmailMessage
from datetime import datetime
from typing import Optional
import re


def parse_eml(file_path: str) -> dict:
    """Parse an .eml file and return structured header data."""
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    headers = {
        "raw_headers": _get_raw_headers(msg),
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "cc": msg.get("Cc", ""),
        "bcc": msg.get("Bcc", ""),
        "reply_to": msg.get("Reply-To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "in_reply_to": msg.get("In-Reply-To", ""),
        "references": msg.get("References", ""),
        "return_path": msg.get("Return-Path", ""),
        "delivered_to": msg.get("Delivered-To", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "x_mailer": msg.get("X-Mailer", ""),
        "x_sender": msg.get("X-Sender", ""),
        "mime_version": msg.get("MIME-Version", ""),
        "content_type": msg.get("Content-Type", ""),
        "user_agent": msg.get("User-Agent", ""),
        "x_authentication_results": msg.get("X-Authentication-Results", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "arc_authentication_results": msg.get("ARC-Authentication-Results", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),
        "x_google_dkim_signature": msg.get("X-Google-DKIM-Signature", ""),
        "received": msg.get_all("Received", []),
        "x_received": msg.get_all("X-Received", []),
        "all_headers": _get_all_headers(msg),
        "all_header_names": list(msg.keys()),
        "body_preview": _get_body_preview(msg),
        "attachments": _get_attachment_info(msg),
    }

    # Parse structured fields
    headers["from_parsed"] = _parse_email_address(headers["from"])
    headers["to_parsed"] = _parse_email_addresses(headers["to"])
    headers["reply_to_parsed"] = _parse_email_address(headers["reply_to"])
    headers["return_path_parsed"] = _parse_email_address(headers["return_path"])
    headers["date_parsed"] = _parse_date(headers["date"])

    # Forwarded email detection
    headers["is_forwarded"] = _detect_forwarded(headers)

    # Full body extraction (not just preview)
    headers["body_text"] = _get_body_text(msg, max_len=5000)
    headers["body_html"] = _get_body_html(msg, max_len=10000)

    return headers


def _get_raw_headers(msg: EmailMessage) -> str:
    """Get raw header block as string."""
    parts = []
    for key in msg.keys():
        for val in msg.get_all(key, []):
            parts.append(f"{key}: {val}")
    return "\n".join(parts)


def _get_all_headers(msg: EmailMessage) -> dict:
    """Get all headers as a dict of lists."""
    result = {}
    for key in msg.keys():
        vals = msg.get_all(key, [])
        if key in result:
            result[key].extend(vals)
        else:
            result[key] = vals
    return result


def _get_body_preview(msg: EmailMessage, max_len: int = 500) -> str:
    """Get a preview of the email body."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        return payload[:max_len]
        else:
            payload = msg.get_content()
            if isinstance(payload, str):
                return payload[:max_len]
    except Exception:
        pass
    return ""


def _get_attachment_info(msg: EmailMessage) -> list:
    """Get attachment metadata including SHA256 hash."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                filename = part.get_filename() or "unnamed"
                raw_content = part.get_payload(decode=True) or b""
                size = len(raw_content)
                ct = part.get_content_type()

                # Compute hashes
                md5 = hashlib.md5(raw_content).hexdigest() if raw_content else ""
                sha256 = hashlib.sha256(raw_content).hexdigest() if raw_content else ""

                attachments.append({
                    "filename": filename,
                    "content_type": ct,
                    "size_bytes": size,
                    "md5": md5,
                    "sha256": sha256,
                })
    return attachments


def _parse_email_address(raw: str) -> dict:
    """Parse a single email address into name and addr."""
    if not raw:
        return {"name": "", "address": ""}
    name, addr = email.utils.parseaddr(raw)
    return {"name": name, "address": addr.lower().strip()}


def _parse_email_addresses(raw: str) -> list:
    """Parse multiple email addresses."""
    if not raw:
        return []
    parsed = email.utils.getaddresses([raw])
    return [{"name": n, "address": a.lower().strip()} for n, a in parsed]


def _parse_date(raw: str) -> Optional[str]:
    """Parse email date header."""
    if not raw:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        return dt.isoformat()
    except Exception:
        return raw


def _detect_forwarded(headers: dict) -> dict:
    """Detect if email was forwarded."""
    indicators = []

    # Check for Forwarded header
    all_headers = headers.get("all_headers", {})
    for h_name in ["Forwarded", "X-Forwarded-For", "X-Forwarded-To",
                    "Resent-From", "Resent-To", "Resent-Date", "Resent-Message-ID"]:
        if h_name in all_headers:
            indicators.append(h_name)

    # Check subject for FWD:/FW: prefix
    subject = headers.get("subject", "")
    if re.match(r'^(FWD?|FW)\s*:', subject, re.IGNORECASE):
        indicators.append("Subject prefix (FWD:/FW:)")

    # Check body for forwarded message markers
    body = headers.get("body_preview", "")
    forwarded_markers = [
        "---------- Forwarded message",
        "Begin forwarded message",
        "Original Message",
        "-----Original Message-----",
        "From:",  # In body context, indicates forwarded content
    ]
    for marker in forwarded_markers:
        if marker.lower() in body.lower():
            indicators.append(f"Body marker: {marker}")
            break

    return {
        "is_forwarded": len(indicators) > 0,
        "indicators": indicators,
    }


def _get_body_text(msg: EmailMessage, max_len: int = 5000) -> str:
    """Get full plain text body."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        return payload[:max_len]
        else:
            if msg.get_content_type() == "text/plain":
                payload = msg.get_content()
                if isinstance(payload, str):
                    return payload[:max_len]
    except Exception:
        pass
    return ""


def _get_body_html(msg: EmailMessage, max_len: int = 10000) -> str:
    """Get full HTML body."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/html":
                    payload = part.get_content()
                    if isinstance(payload, str):
                        return payload[:max_len]
        else:
            if msg.get_content_type() == "text/html":
                payload = msg.get_content()
                if isinstance(payload, str):
                    return payload[:max_len]
    except Exception:
        pass
    return ""
