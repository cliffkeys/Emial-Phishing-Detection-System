import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from email.utils import parseaddr


@dataclass
class SenderAnalysisResult:
    """Detailed sender and identity spoofing evaluation."""
    sender_email: str = ""
    sender_domain: str = ""
    display_name: str = ""
    reply_to_email: str = ""
    reply_to_domain: str = ""
    sender_risk_score: float = 0.0
    is_spoofed_display_name: bool = False
    is_reply_to_mismatch: bool = False
    is_free_provider_impersonation: bool = False
    is_lookalike_domain: bool = False
    risk_reasons: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)


class SenderAnalyzer:
    """
    Evaluates sender identity, display-name deception, domain spoofing, and Reply-To consistency.
    """

    FREE_EMAIL_DOMAINS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
        "aol.com", "icloud.com", "mail.com", "protonmail.com", "proton.me",
        "zoho.com", "yandex.com", "gmx.com", "fastmail.com"
    }

    HIGH_VALUE_ORGANIZATIONS = {
        "microsoft": ["microsoft.com", "office365.com", "office.com", "live.com", "outlook.com"],
        "paypal": ["paypal.com", "paypal-communication.com"],
        "google": ["google.com", "gmail.com", "youtube.com"],
        "apple": ["apple.com", "icloud.com"],
        "amazon": ["amazon.com", "aws.amazon.com"],
        "netflix": ["netflix.com"],
        "chase": ["chase.com", "jpmorganchase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "docusign": ["docusign.com"],
        "dropbox": ["dropbox.com"],
        "irs": ["irs.gov"],
        "fedex": ["fedex.com"],
        "dhl": ["dhl.com"],
        "ups": ["ups.com"],
    }

    # Common generic authority roles often faked
    GENERIC_AUTHORITY_NAMES = [
        "it support", "it helpdesk", "security team", "account team",
        "fraud department", "administrator", "billing department",
        "system administrator", "customer care", "compliance department"
    ]

    @classmethod
    def analyze_sender(
        cls,
        sender_raw: str,
        reply_to_raw: Optional[str] = None,
        claimed_subject: Optional[str] = None,
    ) -> SenderAnalysisResult:
        """Thoroughly analyzes sender headers, domains, and display names."""
        result = SenderAnalysisResult()
        
        display_name, sender_addr = parseaddr(sender_raw or "")
        result.display_name = display_name.strip()
        result.sender_email = sender_addr.strip()
        result.sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

        if reply_to_raw and reply_to_raw.strip():
            _, rt_addr = parseaddr(reply_to_raw.strip())
            result.reply_to_email = rt_addr.strip()
            result.reply_to_domain = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""

        score = 0.0

        if not result.sender_domain:
            result.risk_reasons.append("Sender email address is missing or invalid domain format.")
            result.sender_risk_score = 30.0
            return result

        disp_lower = result.display_name.lower()
        sender_domain_clean = result.sender_domain.lower()

        # 1. Brand Impersonation in Display Name vs Actual Sender Domain
        for brand, legit_domains in cls.HIGH_VALUE_ORGANIZATIONS.items():
            if brand in disp_lower:
                is_legit_domain = any(
                    sender_domain_clean == d or sender_domain_clean.endswith("." + d)
                    for d in legit_domains
                )
                if not is_legit_domain:
                    result.is_spoofed_display_name = True
                    score += 45.0
                    reason = (
                        f"Display name claims identity of '{brand.title()}' "
                        f"but email is sent from unrelated domain '{result.sender_domain}'."
                    )
                    result.risk_reasons.append(reason)
                    result.indicators.append({
                        "category": "SENDER",
                        "indicator_name": "Display Name Brand Impersonation",
                        "description": reason,
                        "severity": "CRITICAL",
                        "score_impact": 40,
                    })

        # 2. Generic Authority Name on Free Webmail Provider
        if any(role in disp_lower for role in cls.GENERIC_AUTHORITY_NAMES):
            if sender_domain_clean in cls.FREE_EMAIL_DOMAINS:
                result.is_free_provider_impersonation = True
                score += 35.0
                reason = (
                    f"Official administrative title ('{result.display_name}') used with "
                    f"public free email provider (@{result.sender_domain})."
                )
                result.risk_reasons.append(reason)
                result.indicators.append({
                    "category": "SENDER",
                    "indicator_name": "Free Provider Authority Spoofing",
                    "description": reason,
                    "severity": "HIGH",
                    "score_impact": 35,
                })

        # 3. From vs Reply-To Mismatch
        if result.reply_to_domain and result.reply_to_domain != result.sender_domain:
            result.is_reply_to_mismatch = True
            score += 30.0
            reason = (
                f"Reply-To domain mismatch: Replies will be sent to '{result.reply_to_domain}' "
                f"instead of sender domain '{result.sender_domain}'."
            )
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "SENDER",
                "indicator_name": "Reply-To Address Mismatch",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 30,
            })

        # 4. Lookalike / Typosquatted Domain Heuristics
        for brand, legit_domains in cls.HIGH_VALUE_ORGANIZATIONS.items():
            # e.g., 'paypa1', 'rnicrosoft', 'arnazon'
            typo_variants = [
                brand.replace("l", "1"),
                brand.replace("o", "0"),
                brand.replace("m", "rn"),
                f"{brand}-security",
                f"{brand}-update",
                f"{brand}-support",
                f"{brand}-login",
            ]
            for variant in typo_variants:
                if variant != brand and variant in sender_domain_clean:
                    result.is_lookalike_domain = True
                    score += 40.0
                    reason = f"Potential typosquatted / lookalike sender domain detected: '{result.sender_domain}'."
                    result.risk_reasons.append(reason)
                    result.indicators.append({
                        "category": "SENDER",
                        "indicator_name": "Typosquatted Sender Domain",
                        "description": reason,
                        "severity": "CRITICAL",
                        "score_impact": 40,
                    })
                    break

        # 5. Subdomain nesting spoofing (e.g. paypal.com.evil.net)
        for brand in cls.HIGH_VALUE_ORGANIZATIONS.keys():
            if f"{brand}.com." in sender_domain_clean:
                score += 35.0
                reason = f"Subdomain spoofing pattern detected: '{sender_domain_clean}' mimics authorized organization."
                result.risk_reasons.append(reason)
                result.indicators.append({
                    "category": "SENDER",
                    "indicator_name": "Subdomain Deception",
                    "description": reason,
                    "severity": "HIGH",
                    "score_impact": 35,
                })

        result.sender_risk_score = min(round(score, 1), 100.0)
        return result
