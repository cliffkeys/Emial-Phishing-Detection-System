from datetime import datetime, timezone
import json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from .db import db


class User(UserMixin, db.Model):
    """User account model for authentication and role management."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)  # 'user', 'admin'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    analyses = db.relationship("Analysis", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash and set user password securely using Werkzeug."""
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Verify the password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Analysis(db.Model):
    """Stores full analysis records for submitted emails with complete explainability metadata."""
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    
    # Email Metadata
    sender = db.Column(db.String(255), default="Unknown", nullable=False, index=True)
    recipient = db.Column(db.String(255), default="", nullable=True)
    subject = db.Column(db.String(512), default="No Subject", nullable=False, index=True)
    email_body_snippet = db.Column(db.Text, default="", nullable=True)  # Minimized preview for privacy
    raw_headers = db.Column(db.Text, default="", nullable=True)

    # Multi-Vector Sub-Scores (0 to 100)
    spam_score = db.Column(db.Float, default=0.0, nullable=False)
    phishing_score = db.Column(db.Float, default=0.0, nullable=False)
    url_risk_score = db.Column(db.Float, default=0.0, nullable=False)
    sender_risk_score = db.Column(db.Float, default=0.0, nullable=False)
    attachment_risk_score = db.Column(db.Float, default=0.0, nullable=False)
    header_risk_score = db.Column(db.Float, default=0.0, nullable=False)
    html_risk_score = db.Column(db.Float, default=0.0, nullable=False)

    # Overall Synthesis
    overall_risk_score = db.Column(db.Float, default=0.0, nullable=False, index=True)
    classification = db.Column(db.String(32), default="SAFE", nullable=False, index=True)  # SAFE, SPAM, PHISHING, SUSPICIOUS
    risk_level = db.Column(db.String(32), default="LOW", nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Confidence metrics
    ml_confidence = db.Column(db.Float, default=0.0, nullable=False)
    risk_confidence = db.Column(db.Float, default=0.0, nullable=False)

    # Explanations & dynamic advice
    recommendations_json = db.Column(db.Text, default="[]", nullable=False)
    summary_json = db.Column(db.Text, default="{}", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    url_analyses = db.relationship("URLAnalysis", backref="analysis", lazy="joined", cascade="all, delete-orphan")
    indicators = db.relationship("DetectionIndicator", backref="analysis", lazy="joined", cascade="all, delete-orphan")

    @property
    def recommendations(self):
        try:
            return json.loads(self.recommendations_json) if self.recommendations_json else []
        except Exception:
            return []

    @recommendations.setter
    def recommendations(self, val):
        self.recommendations_json = json.dumps(val)

    @property
    def summary_data(self):
        try:
            return json.loads(self.summary_json) if self.summary_json else {}
        except Exception:
            return {}

    @summary_data.setter
    def summary_data(self, val):
        self.summary_json = json.dumps(val)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "email_body_snippet": self.email_body_snippet,
            "spam_score": round(self.spam_score, 1),
            "phishing_score": round(self.phishing_score, 1),
            "url_risk_score": round(self.url_risk_score, 1),
            "sender_risk_score": round(self.sender_risk_score, 1),
            "attachment_risk_score": round(self.attachment_risk_score, 1),
            "header_risk_score": round(self.header_risk_score, 1),
            "html_risk_score": round(self.html_risk_score, 1),
            "overall_risk_score": round(self.overall_risk_score, 1),
            "classification": self.classification,
            "risk_level": self.risk_level,
            "ml_confidence": round(self.ml_confidence, 1),
            "risk_confidence": round(self.risk_confidence, 1),
            "recommendations": self.recommendations,
            "summary_data": self.summary_data,
            "urls_count": len(self.url_analyses),
            "indicators_count": len(self.indicators),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    def __repr__(self) -> str:
        return f"<Analysis {self.id} - {self.classification} ({self.overall_risk_score})>"


class URLAnalysis(db.Model):
    """Detailed structural analysis for every URL extracted from email."""
    __tablename__ = "url_analyses"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), default="", nullable=False)
    is_https = db.Column(db.Boolean, default=False, nullable=False)
    has_ip = db.Column(db.Boolean, default=False, nullable=False)
    is_shortener = db.Column(db.Boolean, default=False, nullable=False)
    suspicious_tld = db.Column(db.Boolean, default=False, nullable=False)
    has_punycode = db.Column(db.Boolean, default=False, nullable=False)
    has_at_symbol = db.Column(db.Boolean, default=False, nullable=False)
    subdomain_count = db.Column(db.Integer, default=0, nullable=False)
    length = db.Column(db.Integer, default=0, nullable=False)
    risk_score = db.Column(db.Float, default=0.0, nullable=False)
    risk_reasons_json = db.Column(db.Text, default="[]", nullable=False)

    @property
    def risk_reasons(self):
        try:
            return json.loads(self.risk_reasons_json) if self.risk_reasons_json else []
        except Exception:
            return []

    @risk_reasons.setter
    def risk_reasons(self, val):
        self.risk_reasons_json = json.dumps(val)

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "domain": self.domain,
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


class DetectionIndicator(db.Model):
    """Specific flagged indicator or heuristic trigger for explainability."""
    __tablename__ = "detection_indicators"

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analyses.id"), nullable=False, index=True)
    category = db.Column(db.String(64), nullable=False)  # URGENCY, CREDENTIAL, FINANCIAL, SENDER, ATTACHMENT, URL, HEADER, HTML
    indicator_name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(32), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    score_impact = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "indicator_name": self.indicator_name,
            "description": self.description,
            "severity": self.severity,
            "score_impact": self.score_impact,
        }


class AuditLog(db.Model):
    """Security and activity audit log."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    ip_address = db.Column(db.String(64), default="", nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    details = db.Column(db.Text, default="", nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "System/Anonymous",
            "action": self.action,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "details": self.details,
        }
