import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from email_parser.parser import ParsedEmail
from ml.model_manager import ModelManager, MLPredictionResult
from .url_analyzer import URLAnalyzer, URLAnalysisResult
from .text_analyzer import TextAnalyzer, TextAnalysisResult
from .sender_analyzer import SenderAnalyzer, SenderAnalysisResult
from .header_analyzer import HeaderAnalyzer, HeaderAnalysisResult
from .attachment_analyzer import AttachmentAnalyzer, AttachmentAnalysisResult
from .html_analyzer import HTMLAnalyzer, HTMLAnalysisResult


@dataclass
class CompleteAnalysisResult:
    """Consolidated end-to-end multi-vector email threat detection result."""
    # Metadata
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    body_snippet: str = ""
    raw_headers: str = ""

    # Classifications
    classification: str = "SAFE"      # SAFE, SPAM, PHISHING, SUSPICIOUS
    risk_level: str = "LOW"           # LOW, MEDIUM, HIGH, CRITICAL
    overall_risk_score: float = 0.0   # 0 to 100
    ml_confidence: float = 0.0        # ML prediction confidence (0 to 100)
    risk_confidence: float = 0.0      # Heuristic engine confidence (0 to 100)

    # Sub-Vector Scores (0 to 100)
    spam_score: float = 0.0
    phishing_score: float = 0.0
    url_risk_score: float = 0.0
    sender_risk_score: float = 0.0
    attachment_risk_score: float = 0.0
    header_risk_score: float = 0.0
    html_risk_score: float = 0.0

    # Detailed sub-results
    url_analysis: Optional[URLAnalysisResult] = None
    text_analysis: Optional[TextAnalysisResult] = None
    sender_analysis: Optional[SenderAnalysisResult] = None
    header_analysis: Optional[HeaderAnalysisResult] = None
    attachment_analysis: Optional[AttachmentAnalysisResult] = None
    html_analysis: Optional[HTMLAnalysisResult] = None
    ml_result: Optional[MLPredictionResult] = None

    # Explainability and Action Items
    reasons: List[str] = field(default_factory=list)
    safe_indicators: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    summary_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "classification": self.classification,
            "risk_level": self.risk_level,
            "overall_risk_score": round(self.overall_risk_score, 1),
            "ml_confidence": round(self.ml_confidence, 1),
            "risk_confidence": round(self.risk_confidence, 1),
            "scores": {
                "spam_score": round(self.spam_score, 1),
                "phishing_score": round(self.phishing_score, 1),
                "url_risk_score": round(self.url_risk_score, 1),
                "sender_risk_score": round(self.sender_risk_score, 1),
                "attachment_risk_score": round(self.attachment_risk_score, 1),
                "header_risk_score": round(self.header_risk_score, 1),
                "html_risk_score": round(self.html_risk_score, 1),
            },
            "reasons": self.reasons,
            "safe_indicators": self.safe_indicators,
            "recommendations": self.recommendations,
            "indicators": self.indicators,
            "urls": [u.to_dict() for u in (self.url_analysis.urls_details if self.url_analysis else [])],
            "attachments": [a.to_dict() for a in (self.attachment_analysis.attachments_details if self.attachment_analysis else [])],
            "auth_summary": self.header_analysis.auth_summary if self.header_analysis else "",
        }


class HybridRiskEngine:
    """
    Central Decision and Synthesis Engine that integrates Machine Learning probabilities
    with multi-vector cybersecurity rule heuristics.
    """

    @classmethod
    def evaluate(cls, parsed: ParsedEmail, ml_manager: Optional[ModelManager] = None) -> CompleteAnalysisResult:
        """Executes full diagnostic pipeline on a ParsedEmail instance."""
        result = CompleteAnalysisResult(
            sender=parsed.sender_email or parsed.sender_raw or "Unknown",
            recipient=parsed.recipient_email or parsed.recipient_raw or "",
            subject=parsed.subject or "No Subject",
            body_snippet=(parsed.body_plain[:200] + "...") if len(parsed.body_plain) > 200 else parsed.body_plain,
            raw_headers=parsed.auth_results_raw or "",
        )

        # 1. Machine Learning Inference
        if ml_manager is None:
            ml_manager = ModelManager.get_instance()
        ml_res = ml_manager.predict(parsed.full_text)
        result.ml_result = ml_res
        result.ml_confidence = ml_res.confidence
        result.spam_score = ml_res.spam_probability

        # 2. Text Linguistic Analysis
        text_res = TextAnalyzer.analyze_text(parsed.full_text)
        result.text_analysis = text_res
        result.phishing_score = text_res.phishing_score

        # 3. URL Structural Analysis
        url_res = URLAnalyzer.analyze_urls(parsed.urls)
        result.url_analysis = url_res
        result.url_risk_score = url_res.aggregate_risk_score

        # 4. Sender Identity & Spoofing Analysis
        sender_res = SenderAnalyzer.analyze_sender(
            sender_raw=parsed.sender_raw,
            reply_to_raw=parsed.reply_to_raw,
            claimed_subject=parsed.subject
        )
        result.sender_analysis = sender_res
        result.sender_risk_score = sender_res.sender_risk_score

        # 5. Header Authentication Analysis
        header_res = HeaderAnalyzer.analyze_headers(
            raw_headers=parsed.auth_results_raw,
            headers_dict=parsed.headers,
            received_list=parsed.received_headers
        )
        result.header_analysis = header_res
        result.header_risk_score = header_res.header_risk_score

        # 6. Attachment Metadata Analysis
        att_res = AttachmentAnalyzer.analyze_attachments(parsed.attachments)
        result.attachment_analysis = att_res
        result.attachment_risk_score = att_res.attachment_risk_score

        # 7. HTML Deceptive Elements Analysis
        html_res = HTMLAnalyzer.analyze_html(
            html_content=parsed.body_html,
            html_links=parsed.html_links,
            has_forms=parsed.html_has_forms,
            has_password_inputs=parsed.html_has_password_input,
            has_scripts=parsed.html_has_scripts,
            has_iframes=parsed.html_has_iframes,
            has_hidden_elements=parsed.html_has_hidden_elements,
        )
        result.html_analysis = html_res
        result.html_risk_score = html_res.html_risk_score

        # Aggregate all detected indicators
        all_indicators = []
        all_indicators.extend(text_res.indicators)
        all_indicators.extend(url_res.indicators)
        all_indicators.extend(sender_res.indicators)
        all_indicators.extend(header_res.indicators)
        all_indicators.extend(att_res.indicators)
        all_indicators.extend(html_res.indicators)
        result.indicators = all_indicators

        # 8. Compute Hybrid Synthesis Score
        # Standard weighted distribution
        weighted_score = (
            (result.phishing_score * 0.25) +
            (result.url_risk_score * 0.25) +
            (result.sender_risk_score * 0.20) +
            (result.attachment_risk_score * 0.15) +
            (result.spam_score * 0.10) +
            (result.html_risk_score * 0.05)
        )

        # Critical Escalation Rules:
        # If severe critical threats are present (executable attachment, deceptive href spoofing, high-risk URL + credential harvesting), escalate overall score.
        critical_escalations = []
        if att_res.max_attachment_risk >= 50.0:
            critical_escalations.append(85.0)
        if html_res.html_risk_score >= 45.0:
            critical_escalations.append(85.0)
        if url_res.max_risk_score >= 50.0 and text_res.phishing_score >= 25.0:
            critical_escalations.append(88.0)
        if sender_res.is_spoofed_display_name and (url_res.max_risk_score > 30.0 or text_res.phishing_score > 25.0):
            critical_escalations.append(90.0)

        if critical_escalations:
            result.overall_risk_score = max(weighted_score, max(critical_escalations))
        else:
            result.overall_risk_score = min(round(weighted_score, 1), 100.0)

        # Determine Risk Level
        score = result.overall_risk_score
        if score >= 80.0:
            result.risk_level = "CRITICAL"
        elif score >= 60.0:
            result.risk_level = "HIGH"
        elif score >= 30.0:
            result.risk_level = "MEDIUM"
        else:
            result.risk_level = "LOW"

        # Determine Final Classification
        is_phishing_vector = (
            result.phishing_score >= 35.0 or
            result.url_risk_score >= 40.0 or
            result.sender_risk_score >= 40.0 or
            result.html_risk_score >= 40.0 or
            result.attachment_risk_score >= 40.0
        )

        if score >= 60.0 and is_phishing_vector:
            result.classification = "PHISHING"
        elif score >= 50.0 and result.spam_score >= 60.0 and not is_phishing_vector:
            result.classification = "SPAM"
        elif score >= 30.0:
            result.classification = "SUSPICIOUS"
        elif result.spam_score >= 65.0:
            result.classification = "SPAM"
        else:
            result.classification = "SAFE"

        # Confidence calculation for the heuristic synthesis
        # Heuristic confidence increases with the number of converging indicators or clear negative signals
        if result.indicators:
            heuristic_conf = min(70.0 + len(result.indicators) * 6.0, 99.0)
        else:
            heuristic_conf = 88.0 if result.classification == "SAFE" else 65.0
        result.risk_confidence = round(heuristic_conf, 1)

        # 9. Dynamic Explainability & Recommendations
        cls._generate_explanations_and_recommendations(result, parsed)

        # Summary data payload for persistence
        result.summary_data = {
            "classification": result.classification,
            "risk_level": result.risk_level,
            "overall_risk_score": result.overall_risk_score,
            "ml_confidence": result.ml_confidence,
            "risk_confidence": result.risk_confidence,
            "ml_model_loaded": ml_res.is_model_loaded,
            "ml_spam_prob": ml_res.spam_probability,
            "ml_ham_prob": ml_res.ham_probability,
            "total_urls": len(parsed.urls),
            "total_attachments": len(parsed.attachments),
            "reasons": result.reasons,
            "safe_indicators": result.safe_indicators,
        }

        return result

    @classmethod
    def _generate_explanations_and_recommendations(cls, res: CompleteAnalysisResult, parsed: ParsedEmail) -> None:
        """Generates dynamic, human-readable reasons and actionable security recommendations."""
        reasons = []
        safe_indicators = []
        recommendations = []

        # Positive / Safe signals
        if res.classification == "SAFE":
            safe_indicators.append("No urgent or coercive language detected in email content.")
            safe_indicators.append("No credential harvesting requests or suspicious links found.")
            if not parsed.attachments:
                safe_indicators.append("No attachments present, reducing payload threat risk.")
            if res.sender_risk_score == 0:
                safe_indicators.append("Sender display name and domain format appear consistent.")
            if res.url_risk_score == 0:
                safe_indicators.append("All extracted URLs conform to standard structural patterns.")

        # Threat reasons
        for ind in res.indicators:
            reasons.append(f"{ind['indicator_name']}: {ind['description']}")

        if res.ml_result and res.ml_result.is_spam and res.classification in ("SPAM", "PHISHING"):
            reasons.append(f"Machine Learning model identified unsolicited patterns ({res.ml_result.spam_probability}% spam probability).")

        res.reasons = reasons
        res.safe_indicators = safe_indicators

        # Actionable Recommendations based on threat type
        if res.classification == "PHISHING":
            recommendations.append("DO NOT click any links or buttons inside this email.")
            recommendations.append("DO NOT enter login passwords, 2FA codes, or banking details.")
            recommendations.append("Verify the sender's identity through an official external channel (e.g. official website or direct phone call).")
            if res.attachment_risk_score > 0:
                recommendations.append("DO NOT open or download the attached file(s).")
            recommendations.append("Report this message to your organization's IT / Cybersecurity security operations center.")
        elif res.classification == "SPAM":
            recommendations.append("Do not respond to the sender or click promotional links.")
            recommendations.append("Do not purchase items or provide financial details to unsolicited offers.")
            recommendations.append("Mark this message as Spam / Junk in your email client.")
        elif res.classification == "SUSPICIOUS":
            recommendations.append("Exercise caution before interacting with this email.")
            recommendations.append("Inspect links carefully without clicking on them.")
            recommendations.append("Confirm with the sender via a separate trusted communication method if unexpected.")
        else:
            recommendations.append("Email appears legitimate based on structural and linguistic analysis.")
            recommendations.append("Always exercise standard security awareness with unexpected requests.")

        res.recommendations = recommendations
