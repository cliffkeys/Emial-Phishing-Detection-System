import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


@dataclass
class TextAnalysisResult:
    """Detailed result of phishing text heuristics and rule-based NLP analysis."""
    phishing_score: float = 0.0
    spam_text_score: float = 0.0
    category_scores: Dict[str, float] = field(default_factory=dict)
    matched_categories: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    matched_phrases: Dict[str, List[str]] = field(default_factory=dict)


class TextAnalyzer:
    """
    Analyzes email subject and body text for deceptive, coercive, and urgent linguistic patterns.
    Uses configurable multi-vector weighted scoring.
    """

    # Weighted categories of phishing and malicious cues
    CATEGORY_PATTERNS = {
        "URGENCY": {
            "weight": 25.0,
            "patterns": [
                r"\burgent\b",
                r"\bimmediately\b",
                r"\bwithin\s+\d+\s+(hours?|mins?|minutes?|days?)\b",
                r"\baccount\s+(will\s+be\s+)?suspended\b",
                r"\baccount\s+(will\s+be\s+)?terminated\b",
                r"\baction\s+required\b",
                r"\bfinal\s+notice\b",
                r"\bfinal\s+warning\b",
                r"\bimmediate\s+action\b",
                r"\blimited\s+time\b",
                r"\baccess\s+revoked\b",
                r"\bdeactivat(ed|ion)\b",
                r"\bdeadline\b",
                r"\bexpire(s|d)?\s+(today|soon|in\s+\d+\s+hours?)\b",
            ],
            "severity": "HIGH",
            "name": "Urgent / Coercive Language",
            "desc": "High urgency language detected pressuring the recipient into taking hasty action."
        },
        "CREDENTIALS": {
            "weight": 35.0,
            "patterns": [
                r"\bverif(y|ication)\s+(your\s+)?(password|account|identity|credentials|email)\b",
                r"\bconfirm\s+(your\s+)?(identity|password|login|details|credentials)\b",
                r"\breset\s+(your\s+)?password\b",
                r"\benter\s+(your\s+)?(password|credentials|pin|code)\b",
                r"\bupdate\s+(your\s+)?(security|password|login|credentials|profile)\b",
                r"\blogin\s+to\s+(verify|restore|unlock|keep)\b",
                r"\bsign\s*in\s+to\s+(review|verify|update|unlock)\b",
                r"\btwo[- ]factor\b",
                r"\bsecurity\s+code\b",
                r"\bvalidate\s+your\s+account\b",
                r"\bre-enter\s+your\s+password\b",
            ],
            "severity": "CRITICAL",
            "name": "Credential Request / Harvesting",
            "desc": "Solicitation of account passwords, identity credentials, or security codes detected."
        },
        "FINANCIAL": {
            "weight": 25.0,
            "patterns": [
                r"\bwire\s+transfer\b",
                r"\bunauthorized\s+transaction\b",
                r"\bbank\s+account\b",
                r"\bcredit\s+card\b",
                r"\bdebit\s+card\b",
                r"\bpayment\s+(declined|required|overdue|pending)\b",
                r"\btax\s+refund\b",
                r"\bunclaimed\s+(funds|reward|money|refund)\b",
                r"\bbitcoin\b|\bcrypto\b|\bwallet\b",
                r"\blottery\s+(winner|prize|sweepstakes)\b",
                r"\binheritance\b|\bbeneficiary\b",
                r"\bfee\s+of\s+[\$£€]?\d+\b",
            ],
            "severity": "HIGH",
            "name": "Financial / Payment Inconsistency",
            "desc": "References to banking transactions, payment updates, or prize payouts."
        },
        "SECURITY_ALERTS": {
            "weight": 20.0,
            "patterns": [
                r"\bunusual\s+(sign[- ]in|activity|login)\b",
                r"\bunauthorized\s+(access|sign[- ]in|attempt|purchase)\b",
                r"\bsecurity\s+(alert|notice|warning|breach)\b",
                r"\baccount\s+(locked|compromised|restricted|limited)\b",
                r"\bsuspicious\s+activity\b",
                r"\bnew\s+device\s+sign[- ]in\b",
            ],
            "severity": "MEDIUM",
            "name": "Security Alert Simulation",
            "desc": "Simulated security warnings or fake unauthorized access notifications."
        },
        "CALL_TO_ACTION": {
            "weight": 15.0,
            "patterns": [
                r"\bclick\s+(here|the\s+link|below|this\s+link|button)\b",
                r"\bverify\s+now\b",
                r"\bupdate\s+now\b",
                r"\bclaim\s+(reward|prize|offer|gift)\b",
                r"\bdownload\s+(attachment|file|document|invoice)\b",
                r"\bopen\s+(the\s+)?attached\b",
            ],
            "severity": "LOW",
            "name": "Direct Call-to-Action Link",
            "desc": "Direct prompts urging immediate click-through or document execution."
        },
        "SPAM_PROMOTIONAL": {
            "weight": 20.0,
            "patterns": [
                r"\b100%\s+free\b",
                r"\bguaranteed\s+(return|income|profit|approval)\b",
                r"\bmiracle\s+(pill|cure|fat)\b",
                r"\blose\s+\d+\s*lbs\b",
                r"\blow\s+interest\s+loans?\b",
                r"\bno\s+credit\s+check\b",
                r"\bcheap\s+(pharmacy|viagra|cialis|meds)\b",
                r"\bcasino\s+(bonus|spins)\b",
                r"\bdiscount\s+code\b",
                r"\bclearance\s+sale\b",
                r"\bwork\s+from\s+home\b",
            ],
            "severity": "LOW",
            "name": "Promotional / Unsolicited Spam Indicators",
            "desc": "High-frequency promotional, marketing, or illicit sales phrasing."
        }
    }

    @classmethod
    def analyze_text(cls, text: str) -> TextAnalysisResult:
        """
        Scans text against categorized linguistic patterns.
        Computes weighted category scores and returns matched indicators.
        """
        result = TextAnalysisResult()
        if not text:
            return result

        total_phishing_points = 0.0
        total_spam_points = 0.0
        
        for cat_key, cat_data in cls.CATEGORY_PATTERNS.items():
            matched_items = []
            for pattern_str in cat_data["patterns"]:
                regex = re.compile(pattern_str, re.IGNORECASE)
                matches = regex.findall(text)
                if matches:
                    # Collect matching snippets
                    matched_items.append(pattern_str.replace(r"\b", "").replace(r"\s+", " "))

            if matched_items:
                result.matched_categories.append(cat_key)
                result.matched_phrases[cat_key] = matched_items
                
                # Weight calculation: base weight + incremental bonus for multiple matches in same category
                cat_weight = cat_data["weight"]
                intensity_factor = min(1.0 + (len(matched_items) - 1) * 0.2, 1.8)
                score_for_cat = cat_weight * intensity_factor
                result.category_scores[cat_key] = round(score_for_cat, 1)

                if cat_key == "SPAM_PROMOTIONAL":
                    total_spam_points += score_for_cat
                else:
                    total_phishing_points += score_for_cat

                # Add formal indicator for explainability
                result.indicators.append({
                    "category": cat_key,
                    "indicator_name": cat_data["name"],
                    "description": f"{cat_data['desc']} Trigger matches: {', '.join(matched_items[:3])}",
                    "severity": cat_data["severity"],
                    "score_impact": int(min(score_for_cat, 35)),
                })

        # Cap text scores at 100
        result.phishing_score = min(round(total_phishing_points, 1), 100.0)
        result.spam_text_score = min(round(total_spam_points, 1), 100.0)
        return result
