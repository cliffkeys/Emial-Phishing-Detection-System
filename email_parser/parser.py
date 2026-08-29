import re
import email
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, getaddresses
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse


@dataclass
class ParsedEmail:
    """Represents a thoroughly parsed email structure with full metadata and extracted components."""
    sender_raw: str = ""
    sender_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    
    recipient_raw: str = ""
    recipient_email: str = ""
    
    cc: List[str] = field(default_factory=list)
    reply_to_raw: str = ""
    reply_to_email: str = ""
    reply_to_domain: str = ""
    
    subject: str = "No Subject"
    date_str: str = ""
    message_id: str = ""
    return_path: str = ""
    content_type: str = "text/plain"
    
    body_plain: str = ""
    body_html: str = ""
    
    urls: List[str] = field(default_factory=list)
    html_links: List[Dict[str, str]] = field(default_factory=list)  # [{'text': ..., 'href': ...}]
    
    html_has_forms: bool = False
    html_has_password_input: bool = False
    html_has_scripts: bool = False
    html_has_iframes: bool = False
    html_has_hidden_elements: bool = False
    
    attachments: List[Dict[str, Any]] = field(default_factory=list)  # [{'filename': ..., 'extension': ...}]
    
    received_headers: List[str] = field(default_factory=list)
    auth_results_raw: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    
    is_raw_rfc822: bool = False
    parse_warnings: List[str] = field(default_factory=list)

    @property
    def full_text(self) -> str:
        """Returns subject + body for combined text and NLP classification."""
        text_parts = [self.subject]
        if self.body_plain:
            text_parts.append(self.body_plain)
        elif self.body_html:
            # Fallback to stripped HTML
            soup = BeautifulSoup(self.body_html, "html.parser")
            text_parts.append(soup.get_text(separator=" "))
        return " \n ".join(text_parts).strip()


class EmailParser:
    """Robust email parser capable of processing raw RFC 822 emails or form inputs."""

    # Regex for standard URLs
    URL_REGEX = re.compile(
        r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
        re.IGNORECASE,
    )

    @classmethod
    def parse_input(
        cls,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        raw_email: Optional[str] = None,
        attachment_names: Optional[List[str]] = None,
    ) -> ParsedEmail:
        """
        Parses email input from either raw RFC 822 format or standard form fields.
        """
        if raw_email and raw_email.strip():
            # Check if raw_email looks like RFC 822 (contains typical headers)
            is_rfc = any(
                hdr in raw_email[:1000].lower()
                for hdr in ["from:", "to:", "subject:", "received:", "mime-version:"]
            )
            if is_rfc:
                return cls.parse_raw_rfc822(raw_email)

        # Otherwise parse structured fields
        return cls.parse_form_fields(
            sender=sender or "",
            recipient=recipient or "",
            subject=subject or "",
            body=body or "",
            attachment_names=attachment_names or [],
        )

    @classmethod
    def parse_raw_rfc822(cls, raw_text: str) -> ParsedEmail:
        """Parses a full raw email message string using Python's email standard library."""
        parsed = ParsedEmail(is_raw_rfc822=True)
        try:
            msg = Parser(policy=policy.default).parsestr(raw_text)
        except Exception as e:
            parsed.parse_warnings.append(f"Standard parser issue ({str(e)}), using legacy fallback.")
            try:
                msg = email.message_from_string(raw_text)
            except Exception as e2:
                parsed.parse_warnings.append(f"Failed to parse raw email: {str(e2)}")
                return cls.parse_form_fields(body=raw_text)

        # Extract Headers
        headers_dict = {}
        for k, v in msg.items():
            headers_dict[k.lower()] = str(v)
        parsed.headers = headers_dict

        # From
        parsed.sender_raw = str(msg.get("From", "") or "")
        name, addr = parseaddr(parsed.sender_raw)
        parsed.sender_name = name
        parsed.sender_email = addr
        parsed.sender_domain = addr.split("@")[-1].lower() if "@" in addr else ""

        # To & CC
        parsed.recipient_raw = str(msg.get("To", "") or "")
        _, r_addr = parseaddr(parsed.recipient_raw)
        parsed.recipient_email = r_addr

        cc_raw = str(msg.get("Cc", "") or "")
        if cc_raw:
            parsed.cc = [addr for _, addr in getaddresses([cc_raw]) if addr]

        # Reply-To
        parsed.reply_to_raw = str(msg.get("Reply-To", "") or "")
        _, rt_addr = parseaddr(parsed.reply_to_raw)
        parsed.reply_to_email = rt_addr
        parsed.reply_to_domain = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""

        # Subject & Date & Message-ID
        parsed.subject = str(msg.get("Subject", "No Subject") or "No Subject")
        parsed.date_str = str(msg.get("Date", "") or "")
        parsed.message_id = str(msg.get("Message-ID", "") or "")
        parsed.return_path = str(msg.get("Return-Path", "") or "")
        parsed.content_type = msg.get_content_type()

        # Received & Auth headers
        parsed.received_headers = msg.get_all("Received", []) or []
        auth_hdr = msg.get("Authentication-Results", "") or ""
        spf_hdr = msg.get("Received-SPF", "") or ""
        parsed.auth_results_raw = f"{auth_hdr}\n{spf_hdr}".strip()

        # Extract Body and Attachments
        plain_parts = []
        html_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if filename or "attachment" in cdispo.lower():
                    # Attachment detected
                    ext = filename.split(".")[-1].lower() if (filename and "." in filename) else ""
                    parsed.attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "extension": f".{ext}" if ext else "",
                        "content_type": ctype,
                        "disposition": cdispo,
                    })
                elif ctype == "text/plain" and "attachment" not in cdispo.lower():
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            plain_parts.append(payload.decode(charset, errors="replace"))
                        else:
                            plain_parts.append(str(part.get_payload() or ""))
                    except Exception:
                        plain_parts.append(str(part.get_payload() or ""))
                elif ctype == "text/html" and "attachment" not in cdispo.lower():
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            html_parts.append(payload.decode(charset, errors="replace"))
                        else:
                            html_parts.append(str(part.get_payload() or ""))
                    except Exception:
                        html_parts.append(str(part.get_payload() or ""))
        else:
            ctype = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    content = payload.decode(charset, errors="replace")
                else:
                    content = str(msg.get_payload() or "")
            except Exception:
                content = str(msg.get_payload() or "")

            if ctype == "text/html":
                html_parts.append(content)
            else:
                plain_parts.append(content)

        parsed.body_plain = "\n".join(plain_parts).strip()
        parsed.body_html = "\n".join(html_parts).strip()

        # Parse URLs and HTML features
        cls._extract_urls_and_html_features(parsed)
        return parsed

    @classmethod
    def parse_form_fields(
        cls,
        sender: str = "",
        recipient: str = "",
        subject: str = "",
        body: str = "",
        attachment_names: Optional[List[str]] = None,
    ) -> ParsedEmail:
        """Parses individual form submission fields."""
        parsed = ParsedEmail(
            sender_raw=sender.strip(),
            recipient_raw=recipient.strip(),
            subject=subject.strip() or "No Subject",
            is_raw_rfc822=False,
        )

        name, addr = parseaddr(parsed.sender_raw)
        parsed.sender_name = name
        parsed.sender_email = addr if addr else parsed.sender_raw
        if "@" in parsed.sender_email:
            parsed.sender_domain = parsed.sender_email.split("@")[-1].lower()

        _, r_addr = parseaddr(parsed.recipient_raw)
        parsed.recipient_email = r_addr if r_addr else parsed.recipient_raw

        # Detect if body is HTML or Plaintext
        body_clean = body.strip()
        if "<html" in body_clean.lower() or "<div" in body_clean.lower() or "<p>" in body_clean.lower() or "<a " in body_clean.lower():
            parsed.body_html = body_clean
            soup = BeautifulSoup(body_clean, "html.parser")
            parsed.body_plain = soup.get_text(separator="\n").strip()
        else:
            parsed.body_plain = body_clean

        # Attachments metadata from list
        if attachment_names:
            for fname in attachment_names:
                if fname and fname.strip():
                    name_clean = fname.strip()
                    ext = name_clean.split(".")[-1].lower() if "." in name_clean else ""
                    parsed.attachments.append({
                        "filename": name_clean,
                        "extension": f".{ext}" if ext else "",
                        "content_type": "application/octet-stream",
                    })

        # Parse URLs and HTML features
        cls._extract_urls_and_html_features(parsed)
        return parsed

    @classmethod
    def _extract_urls_and_html_features(cls, parsed: ParsedEmail) -> None:
        """Extracts unique URLs and evaluates HTML elements for deceptive structures."""
        urls_found = set()

        # 1. Extract from plain text
        if parsed.body_plain:
            for match in cls.URL_REGEX.finditer(parsed.body_plain):
                u = match.group(0).strip().rstrip(".,;)>'\"]}")
                if u:
                    if not u.startswith(("http://", "https://")):
                        u = "http://" + u
                    urls_found.add(u)

        # 2. Extract and analyze HTML structure if present
        if parsed.body_html:
            try:
                soup = BeautifulSoup(parsed.body_html, "html.parser")
                
                # Check for forms and inputs
                forms = soup.find_all("form")
                if forms:
                    parsed.html_has_forms = True
                    for form in forms:
                        if form.find_all("input", {"type": lambda t: t and t.lower() == "password"}):
                            parsed.html_has_password_input = True

                # Check for scripts and iframes
                if soup.find_all("script"):
                    parsed.html_has_scripts = True
                if soup.find_all("iframe"):
                    parsed.html_has_iframes = True

                # Check for hidden elements
                hidden_tags = soup.find_all(
                    attrs={"style": re.compile(r"(display:\s*none|visibility:\s*hidden|opacity:\s*0|font-size:\s*0)", re.I)}
                )
                if hidden_tags:
                    parsed.html_has_hidden_elements = True

                # Extract <a> links with anchor text
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    anchor_text = a.get_text(separator=" ").strip()
                    if href and not href.startswith(("mailto:", "tel:", "javascript:", "#")):
                        if not href.startswith(("http://", "https://")):
                            href_fixed = "http://" + href
                        else:
                            href_fixed = href
                        urls_found.add(href_fixed)
                        parsed.html_links.append({
                            "text": anchor_text,
                            "href": href_fixed,
                        })

                # Also regex find any remaining raw URLs in HTML text
                raw_html_text = soup.get_text()
                for match in cls.URL_REGEX.finditer(raw_html_text):
                    u = match.group(0).strip().rstrip(".,;)>'\"]}")
                    if u and not u.startswith(("http://", "https://")):
                        u = "http://" + u
                    urls_found.add(u)
            except Exception as e:
                parsed.parse_warnings.append(f"HTML parsing exception: {str(e)}")

        parsed.urls = sorted(list(urls_found))
