import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class DeceptiveLinkDetail:
    """Represents a hyperlink where visible text does not match the actual destination URL."""
    visible_text: str
    actual_href: str
    visible_domain: str
    actual_domain: str
    risk_score: float = 0.0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "visible_text": self.visible_text,
            "actual_href": self.actual_href,
            "visible_domain": self.visible_domain,
            "actual_domain": self.actual_domain,
            "risk_score": round(self.risk_score, 1),
            "reason": self.reason,
        }


@dataclass
class HTMLAnalysisResult:
    """Detailed HTML structural and deceptive elements analysis."""
    html_risk_score: float = 0.0
    has_forms: bool = False
    has_password_inputs: bool = False
    has_scripts: bool = False
    has_iframes: bool = False
    has_hidden_elements: bool = False
    deceptive_links: List[DeceptiveLinkDetail] = field(default_factory=list)
    risk_reasons: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)


class HTMLAnalyzer:
    """
    Analyzes HTML email structures for deceptive hyperlinks, inline credential forms,
    hidden text filter evasion, and active script content.
    """

    @classmethod
    def analyze_html(
        cls,
        html_content: str = "",
        html_links: Optional[List[Dict[str, str]]] = None,
        has_forms: bool = False,
        has_password_inputs: bool = False,
        has_scripts: bool = False,
        has_iframes: bool = False,
        has_hidden_elements: bool = False,
    ) -> HTMLAnalysisResult:
        """Evaluates HTML payload indicators and checks for deceptive anchor mismatch."""
        result = HTMLAnalysisResult(
            has_forms=has_forms,
            has_password_inputs=has_password_inputs,
            has_scripts=has_scripts,
            has_iframes=has_iframes,
            has_hidden_elements=has_hidden_elements,
        )

        score = 0.0

        # 1. Inline Password Fields / Form Harvesting
        if has_password_inputs:
            score += 50.0
            reason = "Direct credential harvesting form (<input type='password'>) embedded inside email body."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HTML",
                "indicator_name": "Embedded Password Input Form",
                "description": reason,
                "severity": "CRITICAL",
                "score_impact": 50,
            })
        elif has_forms:
            score += 25.0
            reason = "Interactive HTML <form> detected in email. Legitimate services do not collect data directly in email forms."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HTML",
                "indicator_name": "Interactive Form Embedded",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 25,
            })

        # 2. Embedded Scripts
        if has_scripts:
            score += 35.0
            reason = "Executable JavaScript <script> tags present in email HTML payload."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HTML",
                "indicator_name": "Active JavaScript Content",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 35,
            })

        # 3. Embedded IFrames
        if has_iframes:
            score += 30.0
            reason = "Embedded <iframe> tag detected. Often used for unauthorized remote content loading or clickjacking."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HTML",
                "indicator_name": "Embedded IFrame Container",
                "description": reason,
                "severity": "HIGH",
                "score_impact": 30,
            })

        # 4. Hidden Text Filter Evasion
        if has_hidden_elements:
            score += 20.0
            reason = "Hidden zero-opacity or collapsed HTML elements detected (anti-spam filter evasion technique)."
            result.risk_reasons.append(reason)
            result.indicators.append({
                "category": "HTML",
                "indicator_name": "Hidden Text Filter Evasion",
                "description": reason,
                "severity": "MEDIUM",
                "score_impact": 20,
            })

        # 5. Deceptive Link Anchor Analysis (Visible text claims domain X, but href points to domain Y)
        if html_links:
            for link in html_links:
                v_text = link.get("text", "").strip()
                href = link.get("href", "").strip()
                
                # Check if visible text looks like a URL or domain
                if "." in v_text and "/" in v_text or v_text.startswith(("http://", "https://", "www.")):
                    # Parse visible domain
                    try:
                        v_target = v_text if v_text.startswith(("http://", "https://")) else f"http://{v_text}"
                        v_domain = urlparse(v_target).netloc.lower().split(":")[0]
                        actual_domain = urlparse(href).netloc.lower().split(":")[0]

                        # Strip 'www.' prefix for comparison
                        v_domain_clean = v_domain.replace("www.", "")
                        actual_domain_clean = actual_domain.replace("www.", "")

                        if v_domain_clean and actual_domain_clean and v_domain_clean != actual_domain_clean:
                            deceptive_item = DeceptiveLinkDetail(
                                visible_text=v_text,
                                actual_href=href,
                                visible_domain=v_domain_clean,
                                actual_domain=actual_domain_clean,
                                risk_score=45.0,
                                reason=(
                                    f"Displayed link text '{v_text}' suggests '{v_domain_clean}', "
                                    f"but actually redirects to '{actual_domain_clean}'."
                                )
                            )
                            result.deceptive_links.append(deceptive_item)
                            score += 45.0
                            result.risk_reasons.append(deceptive_item.reason)
                            result.indicators.append({
                                "category": "HTML",
                                "indicator_name": "Deceptive Hyperlink Target Mismatch",
                                "description": deceptive_item.reason,
                                "severity": "CRITICAL",
                                "score_impact": 45,
                            })
                    except Exception:
                        pass

        result.html_risk_score = min(round(score, 1), 100.0)
        return result
