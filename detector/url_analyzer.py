import re
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class SingleURLDetail:
    """Detailed structural indicators for an individual URL."""
    url: str
    domain: str = ""
    scheme: str = ""
    is_https: bool = False
    has_ip: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False
    has_punycode: bool = False
    has_at_symbol: bool = False
    subdomain_count: int = 0
    length: int = 0
    risk_score: float = 0.0
    risk_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "scheme": self.scheme,
            "is_https": self.is_https,
            "has_ip": self.has_ip,
            "is_shortener": self.is_shortener,
            "suspicious_tld": self.suspicious_tld,
            "has_punycode": self.has_punycode,
            "has_at_symbol": self.has_at_symbol,
            "subdomain_count": self.subdomain_count,
            "length": self.length,
            "risk_score": round(self.risk_score, 1),
            "risk_reasons": self.risk_reasons,
        }


@dataclass
class URLAnalysisResult:
    """Aggregate result across all URLs analyzed in an email."""
    total_urls: int = 0
    max_risk_score: float = 0.0
    aggregate_risk_score: float = 0.0
    urls_details: List[SingleURLDetail] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)


class URLAnalyzer:
    """
    Performs static, lexical, and structural analysis of URLs to detect phishing and malicious patterns
    WITHOUT connecting to or fetching the remote servers.
    """

    # Commonly abused high-risk or free top-level domains in phishing
    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "club", "buzz", "tk", "ml", "ga", "cf", "gq", 
        "cc", "pw", "icu", "cam", "loan", "win", "stream", "download", "racing",
        "accountant", "faith", "date", "review", "country", "kim", "cricket", "science"
    }

    # Known URL shortener services often used to obfuscate phishing destinations
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
        "rebrand.ly", "goo.gl", "tiny.cc", "bc.vc", "shorturl.at", "bl.ink", "trib.al"
    }

    # Common brand targets for domain spoofing / brand impersonation
    TARGET_BRANDS = {
        "paypal": ["paypal.com", "paypal-communication.com", "paypal-corp.com"],
        "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com", "sharepoint.com", "windows.com"],
        "google": ["google.com", "gmail.com", "youtube.com", "google.co.uk", "google.org", "drive.google.com"],
        "apple": ["apple.com", "icloud.com", "appleid.apple.com"],
        "amazon": ["amazon.com", "amazon.co.uk", "aws.amazon.com", "amazon.de"],
        "netflix": ["netflix.com"],
        "facebook": ["facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com"],
        "chase": ["chase.com", "jpmorganchase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "docusign": ["docusign.com", "docusign.net"],
        "dropbox": ["dropbox.com"],
        "linkedin": ["linkedin.com"],
        "adobe": ["adobe.com"],
    }

    # Suspicious path or query tokens
    SUSPICIOUS_PATH_KEYWORDS = {
        "login", "signin", "sign-in", "log-in", "verify", "verification", "secure", "security",
        "account", "update", "banking", "password", "pwd", "credential", "auth", "authorize",
        "webscr", "confirm", "validation", "recover", "wallet", "checkpoint", "session", "suspended"
    }

    IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

    @classmethod
    def analyze_urls(cls, urls: List[str]) -> URLAnalysisResult:
        """Analyzes a list of URLs and produces detailed per-URL and aggregate risk scores."""
        result = URLAnalysisResult(total_urls=len(urls))
        if not urls:
            return result

        details = []
        max_score = 0.0
        scores_sum = 0.0

        for url_str in urls:
            single = cls.analyze_single_url(url_str)
            details.append(single)
            scores_sum += single.risk_score
            if single.risk_score > max_score:
                max_score = single.risk_score

            # Add indicators for explainability
            for reason in single.risk_reasons:
                result.indicators.append({
                    "category": "URL",
                    "indicator_name": "Suspicious URL Characteristic",
                    "description": f"URL '{single.url[:60]}...': {reason}",
                    "severity": "HIGH" if single.risk_score >= 60 else "MEDIUM",
                    "score_impact": int(min(single.risk_score, 30)),
                })

        result.urls_details = details
        result.max_risk_score = round(max_score, 1)
        # Aggregate score takes highest URL risk + minor weighting of multiple suspicious links
        additional_penalty = min(len(urls) * 3.0, 15.0) if max_score > 30 else 0.0
        result.aggregate_risk_score = min(round(max_score + additional_penalty, 1), 100.0)

        return result

    @classmethod
    def analyze_single_url(cls, raw_url: str) -> SingleURLDetail:
        """Evaluates an individual URL on multiple structural and lexical dimensions."""
        detail = SingleURLDetail(url=raw_url, length=len(raw_url))
        score = 0.0

        try:
            parsed = urlparse(raw_url)
        except Exception:
            detail.risk_reasons.append("Malformed URL structure could not be parsed.")
            detail.risk_score = 40.0
            return detail

        detail.scheme = (parsed.scheme or "http").lower()
        detail.is_https = detail.scheme == "https"
        netloc = parsed.netloc.lower()
        
        # Strip port if present for domain analysis
        host = netloc.split(":")[0] if ":" in netloc else netloc
        detail.domain = host

        # 1. Check IP address as hostname (common phishing indicator)
        if cls.IP_PATTERN.match(host):
            detail.has_ip = True
            score += 40.0
            detail.risk_reasons.append("Raw IP address used instead of a registered domain name.")

        # 2. Check for @ symbol (userinfo trick to obscure true host)
        if "@" in raw_url:
            detail.has_at_symbol = True
            score += 35.0
            detail.risk_reasons.append("Contains '@' symbol, which may disguise the real destination host.")

        # 3. Check for Punycode / IDN homograph attacks (e.g. xn--)
        if "xn--" in host:
            detail.has_punycode = True
            score += 30.0
            detail.risk_reasons.append("Punycode (IDN) detected, potential homograph domain deception.")

        # 4. Check for URL shorteners
        if host in cls.URL_SHORTENERS:
            detail.is_shortener = True
            score += 20.0
            detail.risk_reasons.append("URL shortener used, concealing the actual landing destination.")

        # 5. Check TLD
        host_parts = host.split(".")
        if len(host_parts) >= 2:
            tld = host_parts[-1]
            if tld in cls.SUSPICIOUS_TLDS:
                detail.suspicious_tld = True
                score += 25.0
                detail.risk_reasons.append(f"High-risk Top-Level Domain (.{tld}) commonly associated with phishing.")

        # 6. Check Subdomain depth (excessive subdomains)
        if len(host_parts) > 3 and not detail.has_ip:
            detail.subdomain_count = len(host_parts) - 2
            score += 15.0
            detail.risk_reasons.append(f"Excessive subdomain depth ({len(host_parts) - 2} levels).")

        # 7. Check URL Length
        if len(raw_url) > 100:
            score += 10.0
            detail.risk_reasons.append("Excessively long URL string (>100 characters).")

        # 8. Check for Brand Impersonation / Typosquatting in Hostname or Path
        for brand, legitimate_domains in cls.TARGET_BRANDS.items():
            if brand in host:
                # Check if host is actually legitimate for that brand
                is_legit = any(host == legit or host.endswith("." + legit) for legit in legitimate_domains)
                if not is_legit:
                    score += 35.0
                    detail.risk_reasons.append(
                        f"Potential brand impersonation: '{brand}' appears in host '{host}' but domain is not an authorized property."
                    )
            elif brand in parsed.path.lower():
                # Brand in path on an unrelated domain
                is_legit = any(host == legit or host.endswith("." + legit) for legit in legitimate_domains)
                if not is_legit:
                    score += 20.0
                    detail.risk_reasons.append(
                        f"Brand name '{brand}' in URL path on unaffiliated domain '{host}'."
                    )

        # 9. Check for Suspicious Path & Query Keywords
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()
        matched_keywords = [kw for kw in cls.SUSPICIOUS_PATH_KEYWORDS if kw in path_lower or kw in query_lower]
        if matched_keywords:
            score += min(len(matched_keywords) * 8.0, 25.0)
            detail.risk_reasons.append(f"Suspicious authentication/security keywords in URL: {', '.join(matched_keywords[:4])}")

        # 10. Check for Open Redirect query parameters
        redirect_params = ["redirect", "url", "next", "dest", "target", "return", "r", "goto"]
        query_dict = parse_qs(parsed.query)
        for rp in redirect_params:
            if rp in query_dict:
                val = query_dict[rp][0]
                if val.startswith("http://") or val.startswith("https://") or "//" in val:
                    score += 20.0
                    detail.risk_reasons.append(f"Open redirect parameter ('{rp}') detected pointing to an external destination.")
                    break

        # 11. Check Non-standard Port
        if ":" in netloc and not detail.has_ip:
            port = netloc.split(":")[-1]
            if port not in ("80", "443"):
                score += 15.0
                detail.risk_reasons.append(f"Non-standard HTTP port (:{port}) specified in URL.")

        # 12. Non-HTTPS penalty if suspicious keywords or actions present
        if not detail.is_https and (matched_keywords or score > 15.0):
            score += 15.0
            detail.risk_reasons.append("Unencrypted HTTP protocol used for sensitive or authentication action.")

        detail.risk_score = min(round(score, 1), 100.0)
        return detail
