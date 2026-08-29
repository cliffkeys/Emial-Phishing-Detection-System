import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class HeaderAnalysisResult:
    """Detailed email authentication and transport header evaluation."""
    spf_status: str = "Not available"      # Pass, Fail, SoftFail, Neutral, Not available
    dkim_status: str = "Not available"     # Pass, Fail, Not available
    dmarc_status: str = "Not available"    # Pass, Fail, Not available
    header_risk_score: float = 0.0
    received_hops_count: int = 0
    auth_summary: str = "No raw authentication headers provided for inspection."
    risk_reasons: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    educational_notes: Dict[str, str] = field(default_factory=dict)


class HeaderAnalyzer:
    """
    Parses SPF, DKIM, and DMARC authentication headers.
    Provides explainable cybersecurity diagnostics without fabricating absent values.
    """

    EDUCATIONAL_INFO = {
        "SPF": (
            "Sender Policy Framework (SPF) verifies whether the sending mail server IP is authorized "
            "by the domain owner's DNS records."
        ),
        "DKIM": (
            "DomainKeys Identified Mail (DKIM) validates that the email message was cryptographically signed "
            "by the claimed domain and was not altered in transit."
        ),
        "DMARC": (
            "Domain-based Message Authentication, Reporting & Conformance (DMARC) enforces SPF and DKIM alignment "
            "and defines policies (none, quarantine, reject) for unauthenticated emails."
        )
    }

    @classmethod
    def analyze_headers(
        cls,
        raw_headers: str = "",
        headers_dict: Optional[Dict[str, str]] = None,
        received_list: Optional[List[str]] = None,
    ) -> HeaderAnalysisResult:
        """Inspects raw email headers and authentication results."""
        result = HeaderAnalysisResult(educational_notes=cls.EDUCATIONAL_INFO)
        score = 0.0

        headers_str = (raw_headers or "").lower()
        if headers_dict:
            for k, v in headers_dict.items():
                headers_str += f"\n{k.lower()}: {str(v).lower()}"

        if received_list:
            result.received_hops_count = len(received_list)

        if not headers_str.strip():
            result.auth_summary = "Raw transport headers were not supplied. Authentication status could not be verified."
            return result

        # 1. Parse SPF
        if "spf=pass" in headers_str or "received-spf: pass" in headers_str:
            result.spf_status = "Pass"
        elif "spf=fail" in headers_str or "received-spf: fail" in headers_str:
            result.spf_status = "Fail"
            score += 35.0
            reason = "SPF authentication failed: Sending IP is not authorized by the sender domain."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HEADER",
                "indicator_name": "SPF Authentication Failure",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 35,
            })
        elif "spf=softfail" in headers_str:
            result.spf_status = "SoftFail"
            score += 15.0
            reason = "SPF softfail: Sending server IP is not listed in authoritative SPF records."
            result.risk_reasons.append(reason)

        # 2. Parse DKIM
        if "dkim=pass" in headers_str:
            result.dkim_status = "Pass"
        elif "dkim=fail" in headers_str or "dkim=temperror" in headers_str or "dkim=permerror" in headers_str:
            result.dkim_status = "Fail"
            score += 30.0
            reason = "DKIM cryptographic signature verification failed. Message integrity may be compromised."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HEADER",
                "indicator_name": "DKIM Signature Failure",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 30,
            })

        # 3. Parse DMARC
        if "dmarc=pass" in headers_str:
            result.dmarc_status = "Pass"
        elif "dmarc=fail" in headers_str:
            result.dmarc_status = "Fail"
            score += 40.0
            reason = "DMARC policy alignment check failed. Email violates the sender domain's authentication policy."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HEADER",
                "indicator_name": "DMARC Policy Failure",
                "description": reason,
                "severity": "CRITICAL",
                "score_impact": 40,
            })

        # Summary generation
        statuses = []
        if result.spf_status != "Not available":
            statuses.append(f"SPF: {result.spf_status}")
        if result.dkim_status != "Not available":
            statuses.append(f"DKIM: {result.dkim_status}")
        if result.dmarc_status != "Not available":
            statuses.append(f"DMARC: {result.dmarc_status}")

        if statuses:
            result.auth_summary = " | ".join(statuses)
        else:
            result.auth_summary = "Header fields present, but explicit SPF/DKIM/DMARC verdicts were not declared."

        result.header_risk_score = min(round(score, 1), 100.0)
        return result
