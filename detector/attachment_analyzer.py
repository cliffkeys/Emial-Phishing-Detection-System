import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class AttachmentDetail:
    """Evaluation result for an individual attachment metadata record."""
    filename: str
    extension: str
    is_executable: bool = False
    is_macro_enabled: bool = False
    is_double_extension: bool = False
    is_archive: bool = False
    risk_score: float = 0.0
    risk_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "extension": self.extension,
            "is_executable": self.is_executable,
            "is_macro_enabled": self.is_macro_enabled,
            "is_double_extension": self.is_double_extension,
            "is_archive": self.is_archive,
            "risk_score": round(self.risk_score, 1),
            "risk_reasons": self.risk_reasons,
        }


@dataclass
class AttachmentAnalysisResult:
    """Aggregate attachment security analysis result."""
    total_attachments: int = 0
    max_attachment_risk: float = 0.0
    attachment_risk_score: float = 0.0
    attachments_details: List[AttachmentDetail] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)


class AttachmentAnalyzer:
    """
    Performs static metadata and extension analysis on email attachments.
    Never executes or opens submitted attachment payloads.
    """

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta",
        ".cpl", ".pif", ".jar", ".wsf", ".msi", ".com", ".gadget", ".msp"
    }

    MACRO_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".potm", ".ppam"
    }

    ARCHIVE_EXTENSIONS = {
        ".zip", ".rar", ".7z", ".iso", ".img", ".tar", ".gz", ".bz2", ".cab", ".ace"
    }

    SAFE_COMMON_EXTENSIONS = {
        ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".jpg", ".jpeg",
        ".png", ".gif", ".mp4", ".mp3", ".wav"
    }

    SUSPICIOUS_NAME_KEYWORDS = [
        "invoice", "receipt", "payment", "statement", "remittance", "tax",
        "salary", "payroll", "rfq", "quote", "order", "delivery", "wire", "urgent"
    ]

    @classmethod
    def analyze_attachments(cls, attachments: List[Dict[str, Any]]) -> AttachmentAnalysisResult:
        """Analyzes attachment metadata and identifies weaponized or suspicious formats."""
        result = AttachmentAnalysisResult(total_attachments=len(attachments))
        if not attachments:
            return result

        details = []
        max_score = 0.0

        for att in attachments:
            fname = att.get("filename", "unnamed").strip()
            detail = AttachmentDetail(filename=fname, extension="")

            # Extract extension
            name_parts = fname.split(".")
            if len(name_parts) > 1:
                ext = f".{name_parts[-1].lower()}"
                detail.extension = ext
            else:
                ext = ""

            score = 0.0

            # 1. Double extension check (e.g. invoice.pdf.exe)
            if len(name_parts) > 2:
                penultimate_ext = f".{name_parts[-2].lower()}"
                if penultimate_ext in cls.SAFE_COMMON_EXTENSIONS and ext in (cls.EXECUTABLE_EXTENSIONS | cls.MACRO_EXTENSIONS | cls.ARCHIVE_EXTENSIONS):
                    detail.is_double_extension = True
                    score += 50.0
                    reason = f"Deceptive double extension detected ('{fname}'). Disguises malicious payload as benign file."
                    detail.risk_reasons.append(reason)
                    result.indicators.append({
                        "category": "ATTACHMENT",
                        "indicator_name": "Deceptive Double Extension",
                        "description": reason,
                        "severity": "CRITICAL",
                        "score_impact": 50,
                    })

            # 2. Executable / Script Extension check
            if ext in cls.EXECUTABLE_EXTENSIONS:
                detail.is_executable = True
                score += 50.0
                reason = f"High-risk executable/script attachment detected ('{fname}'). Commonly used in malware drops."
                detail.risk_reasons.append(reason)
                result.indicators.append({
                    "category": "ATTACHMENT",
                    "indicator_name": "High-Risk Executable Attachment",
                    "description": reason,
                    "severity": "CRITICAL",
                    "score_impact": 50,
                })

            # 3. Macro-enabled document check
            elif ext in cls.MACRO_EXTENSIONS:
                detail.is_macro_enabled = True
                score += 40.0
                reason = f"Macro-enabled Office document ('{fname}'). Macros can execute unauthorized VBA scripts."
                detail.risk_reasons.append(reason)
                result.indicators.append({
                    "category": "ATTACHMENT",
                    "indicator_name": "Macro-Enabled Office Document",
                    "description": reason,
                    "severity": "HIGH",
                    "score_impact": 40,
                })

            # 4. Archive container check
            elif ext in cls.ARCHIVE_EXTENSIONS:
                detail.is_archive = True
                score += 20.0
                detail.risk_reasons.append(f"Compressed archive container ('{fname}'). May contain obfuscated payloads.")

            # 5. Suspicious keyword + Archive / Executable correlation
            fname_lower = fname.lower()
            if any(kw in fname_lower for kw in cls.SUSPICIOUS_NAME_KEYWORDS):
                if detail.is_executable or detail.is_macro_enabled or detail.is_archive:
                    score += 15.0
                    detail.risk_reasons.append(f"Financial/urgent keyword in payload filename ('{fname}').")

            detail.risk_score = min(round(score, 1), 100.0)
            if detail.risk_score > max_score:
                max_score = detail.risk_score
            details.append(detail)

        result.attachments_details = details
        result.max_attachment_risk = round(max_score, 1)
        result.attachment_risk_score = round(max_score, 1)
        return result
