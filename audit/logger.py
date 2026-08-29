from typing import Optional
from flask import request
from database.db import db
from database.models import AuditLog


def log_audit_event(action: str, details: str = "", user_id: Optional[int] = None) -> None:
    """
    Records an operational security event to the database audit log.
    Captures IP address and user contextual data safely.
    """
    try:
        ip = "127.0.0.1"
        if request:
            # Handle standard reverse-proxy headers safely
            if request.headers.get("X-Forwarded-For"):
                ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
            else:
                ip = request.remote_addr or "127.0.0.1"

        entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip[:64],
            details=details[:1000] if details else ""
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # Avoid breaking primary application flow if logging encounters DB lock
        try:
            db.session.rollback()
        except Exception:
            pass
