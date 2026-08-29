import os
import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_required, current_user
from werkzeug.exceptions import HTTPException

from config import config_by_name, BASE_DIR
from database.db import db
from database.models import User, Analysis, URLAnalysis, DetectionIndicator, AuditLog
from auth.routes import auth_bp
from email_parser.parser import EmailParser
from ml.model_manager import ModelManager
from ml.train_model import train_spam_classifier
from detector.risk_engine import HybridRiskEngine
from reports.report_generator import generate_pdf_report
from audit.logger import log_audit_event


def create_app(config_name: str = None) -> Flask:
    """Application factory for MailShield Email Spam & Phishing Detection System."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    # Ensure necessary directory paths exist safely
    try:
        (BASE_DIR / "instance").mkdir(parents=True, exist_ok=True)
        (BASE_DIR / "models").mkdir(parents=True, exist_ok=True)
        (BASE_DIR / "reports" / "generated").mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


    # Initialize Database & Login Manager
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this security module."
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register Blueprints
    app.register_blueprint(auth_bp)

    # Context Processors & Template Filters
    @app.context_processor
    def inject_global_context():
        return {
            "app_name": "MailShield",
            "app_version": "1.0.0",
            "is_admin": current_user.is_authenticated and current_user.is_admin(),
        }

    # -------------------------------------------------------------
    # MAIN WEB ROUTES
    # -------------------------------------------------------------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        # User-specific or admin-wide metrics
        if current_user.is_admin():
            query = Analysis.query
        else:
            query = Analysis.query.filter_by(user_id=current_user.id)

        total_analyzed = query.count()
        safe_count = query.filter_by(classification="SAFE").count()
        spam_count = query.filter_by(classification="SPAM").count()
        phishing_count = query.filter_by(classification="PHISHING").count()
        suspicious_count = query.filter_by(classification="SUSPICIOUS").count()

        # Risk level counts
        low_risk = query.filter_by(risk_level="LOW").count()
        med_risk = query.filter_by(risk_level="MEDIUM").count()
        high_risk = query.filter_by(risk_level="HIGH").count()
        crit_risk = query.filter_by(risk_level="CRITICAL").count()

        recent_analyses = query.order_by(Analysis.created_at.desc()).limit(6).all()

        return render_template(
            "dashboard.html",
            total_analyzed=total_analyzed,
            safe_count=safe_count,
            spam_count=spam_count,
            phishing_count=phishing_count,
            suspicious_count=suspicious_count,
            low_risk=low_risk,
            med_risk=med_risk,
            high_risk=high_risk,
            crit_risk=crit_risk,
            recent_analyses=recent_analyses,
        )

    @app.route("/analyze", methods=["GET", "POST"])
    @login_required
    def analyze():
        if request.method == "POST":
            input_mode = request.form.get("input_mode", "form")  # 'form' or 'raw'
            
            sender = request.form.get("sender", "")
            recipient = request.form.get("recipient", "")
            subject = request.form.get("subject", "")
            body = request.form.get("body", "")
            raw_email = request.form.get("raw_email", "")
            attachment_names_raw = request.form.get("attachments", "")

            attachment_names = [
                a.strip() for a in attachment_names_raw.split(",") if a.strip()
            ] if attachment_names_raw else []

            # 1. Parse Email
            if input_mode == "raw" and raw_email.strip():
                parsed = EmailParser.parse_input(raw_email=raw_email)
            else:
                parsed = EmailParser.parse_input(
                    sender=sender,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                    attachment_names=attachment_names
                )

            # 2. Execute Multi-Vector Hybrid Detection Pipeline
            ml_manager = ModelManager.get_instance(app.config["MODELS_DIR"])
            result = HybridRiskEngine.evaluate(parsed, ml_manager=ml_manager)

            # 3. Persist Analysis Record
            try:
                analysis = Analysis(
                    user_id=current_user.id,
                    sender=result.sender,
                    recipient=result.recipient,
                    subject=result.subject,
                    email_body_snippet=result.body_snippet,
                    raw_headers=result.raw_headers,
                    spam_score=result.spam_score,
                    phishing_score=result.phishing_score,
                    url_risk_score=result.url_risk_score,
                    sender_risk_score=result.sender_risk_score,
                    attachment_risk_score=result.attachment_risk_score,
                    header_risk_score=result.header_risk_score,
                    html_risk_score=result.html_risk_score,
                    overall_risk_score=result.overall_risk_score,
                    classification=result.classification,
                    risk_level=result.risk_level,
                    ml_confidence=result.ml_confidence,
                    risk_confidence=result.risk_confidence,
                )
                analysis.recommendations = result.recommendations
                analysis.summary_data = result.summary_data

                db.session.add(analysis)
                db.session.flush()  # Obtain analysis.id for child records

                # Save URL analysis records
                if result.url_analysis and result.url_analysis.urls_details:
                    for u in result.url_analysis.urls_details:
                        u_rec = URLAnalysis(
                            analysis_id=analysis.id,
                            url=u.url,
                            domain=u.domain,
                            is_https=u.is_https,
                            has_ip=u.has_ip,
                            is_shortener=u.is_shortener,
                            suspicious_tld=u.suspicious_tld,
                            has_punycode=u.has_punycode,
                            has_at_symbol=u.has_at_symbol,
                            subdomain_count=u.subdomain_count,
                            length=u.length,
                            risk_score=u.risk_score,
                        )
                        u_rec.risk_reasons = u.risk_reasons
                        db.session.add(u_rec)

                # Save Detection Indicators
                if result.indicators:
                    for ind in result.indicators:
                        ind_rec = DetectionIndicator(
                            analysis_id=analysis.id,
                            category=ind.get("category", "GENERAL"),
                            indicator_name=ind.get("indicator_name", "Flagged Pattern"),
                            description=ind.get("description", ""),
                            severity=ind.get("severity", "MEDIUM"),
                            score_impact=ind.get("score_impact", 0),
                        )
                        db.session.add(ind_rec)

                db.session.commit()
                log_audit_event(
                    "EMAIL_ANALYSIS",
                    f"Analyzed email from '{result.sender}' -> {result.classification} ({result.overall_risk_score})",
                    user_id=current_user.id
                )
                flash(f"Analysis completed: Result is {result.classification}", "success")
                return redirect(url_for("result", analysis_id=analysis.id))

            except Exception as e:
                db.session.rollback()
                flash(f"Error saving analysis record: {str(e)}", "danger")

        return render_template("analyze.html")

    @app.route("/result/<int:analysis_id>")
    @login_required
    def result(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            flash("Analysis record not found.", "warning")
            return redirect(url_for("history"))

        # Access control: only owner or admin can view
        if analysis.user_id != current_user.id and not current_user.is_admin():
            flash("Unauthorized to view this analysis record.", "danger")
            return redirect(url_for("dashboard"))

        return render_template("result.html", analysis=analysis)

    @app.route("/history")
    @login_required
    def history():
        page = request.args.get("page", 1, type=int)
        search_query = request.args.get("q", "").strip()
        filter_class = request.args.get("classification", "").strip()
        sort_by = request.args.get("sort", "newest")

        if current_user.is_admin():
            base_query = Analysis.query
        else:
            base_query = Analysis.query.filter_by(user_id=current_user.id)

        if search_query:
            base_query = base_query.filter(
                (Analysis.sender.ilike(f"%{search_query}%")) |
                (Analysis.subject.ilike(f"%{search_query}%"))
            )

        if filter_class in ("SAFE", "SPAM", "PHISHING", "SUSPICIOUS"):
            base_query = base_query.filter_by(classification=filter_class)

        if sort_by == "oldest":
            base_query = base_query.order_by(Analysis.created_at.asc())
        elif sort_by == "highest_risk":
            base_query = base_query.order_by(Analysis.overall_risk_score.desc())
        else:
            base_query = base_query.order_by(Analysis.created_at.desc())

        pagination = base_query.paginate(page=page, per_page=10, error_out=False)
        return render_template(
            "history.html",
            pagination=pagination,
            analyses=pagination.items,
            q=search_query,
            classification=filter_class,
            sort=sort_by,
        )

    @app.route("/history/delete/<int:analysis_id>", methods=["POST"])
    @login_required
    def delete_analysis(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            flash("Analysis record not found.", "warning")
            return redirect(url_for("history"))

        if analysis.user_id != current_user.id and not current_user.is_admin():
            flash("Unauthorized action.", "danger")
            return redirect(url_for("history"))

        try:
            db.session.delete(analysis)
            db.session.commit()
            log_audit_event("ANALYSIS_DELETED", f"Deleted analysis ID: {analysis_id}", user_id=current_user.id)
            flash("Analysis record deleted successfully.", "info")
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to delete record: {str(e)}", "danger")

        return redirect(url_for("history"))

    @app.route("/report/<int:analysis_id>/pdf")
    @login_required
    def download_report_pdf(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            flash("Analysis record not found.", "warning")
            return redirect(url_for("history"))

        if analysis.user_id != current_user.id and not current_user.is_admin():
            flash("Unauthorized access.", "danger")
            return redirect(url_for("dashboard"))

        analysis_dict = analysis.to_dict()
        analysis_dict["indicators"] = [i.to_dict() for i in analysis.indicators]
        pdf_stream = generate_pdf_report(analysis_dict)

        log_audit_event("REPORT_DOWNLOAD", f"Downloaded PDF for Analysis ID: {analysis_id}", user_id=current_user.id)
        return send_file(
            pdf_stream,
            as_attachment=True,
            download_name=f"MailShield_Report_{analysis.id}.pdf",
            mimetype="application/pdf"
        )

    @app.route("/report/<int:analysis_id>/view")
    @login_required
    def view_report_html(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            flash("Analysis record not found.", "warning")
            return redirect(url_for("history"))

        if analysis.user_id != current_user.id and not current_user.is_admin():
            flash("Unauthorized access.", "danger")
            return redirect(url_for("dashboard"))

        return render_template("report.html", analysis=analysis)

    @app.route("/evaluation")
    @login_required
    def evaluation():
        ml_manager = ModelManager.get_instance(app.config["MODELS_DIR"])
        metrics = ml_manager.get_metrics()
        return render_template("evaluation.html", metrics=metrics)

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/admin")
    @login_required
    def admin_dashboard():
        if not current_user.is_admin():
            flash("Access restricted to administrative accounts.", "danger")
            return redirect(url_for("dashboard"))

        users_count = User.query.count()
        analyses_count = Analysis.query.count()
        recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
        users = User.query.order_by(User.created_at.desc()).limit(15).all()

        return render_template(
            "admin.html",
            users_count=users_count,
            analyses_count=analyses_count,
            recent_logs=recent_logs,
            users=users,
        )

    # -------------------------------------------------------------
    # REST API ENDPOINTS
    # -------------------------------------------------------------

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        data = request.get_json() or {}
        sender = data.get("sender", "")
        recipient = data.get("recipient", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        raw_email = data.get("raw_email", "")
        attachments = data.get("attachments", [])

        if not body and not raw_email and not subject:
            return jsonify({"error": "Missing email content. Please provide subject, body, or raw_email."}), 400

        parsed = EmailParser.parse_input(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            raw_email=raw_email,
            attachment_names=attachments if isinstance(attachments, list) else []
        )

        ml_manager = ModelManager.get_instance(app.config["MODELS_DIR"])
        result = HybridRiskEngine.evaluate(parsed, ml_manager=ml_manager)
        return jsonify(result.to_dict()), 200

    @app.route("/api/statistics")
    @login_required
    def api_statistics():
        query = Analysis.query if current_user.is_admin() else Analysis.query.filter_by(user_id=current_user.id)
        return jsonify({
            "total": query.count(),
            "classifications": {
                "SAFE": query.filter_by(classification="SAFE").count(),
                "SPAM": query.filter_by(classification="SPAM").count(),
                "PHISHING": query.filter_by(classification="PHISHING").count(),
                "SUSPICIOUS": query.filter_by(classification="SUSPICIOUS").count(),
            },
            "risk_levels": {
                "LOW": query.filter_by(risk_level="LOW").count(),
                "MEDIUM": query.filter_by(risk_level="MEDIUM").count(),
                "HIGH": query.filter_by(risk_level="HIGH").count(),
                "CRITICAL": query.filter_by(risk_level="CRITICAL").count(),
            }
        })

    @app.route("/api/analysis/<int:analysis_id>")
    @login_required
    def api_get_analysis(analysis_id):
        analysis = db.session.get(Analysis, analysis_id)
        if not analysis:
            return jsonify({"error": "Analysis record not found"}), 404
        if analysis.user_id != current_user.id and not current_user.is_admin():
            return jsonify({"error": "Unauthorized"}), 403
        return jsonify(analysis.to_dict())

    # -------------------------------------------------------------
    # ERROR HANDLERS
    # -------------------------------------------------------------

    @app.errorhandler(400)
    def bad_request_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad Request", "details": str(e)}), 400
        return render_template("404.html", error_code=400, error_message="Bad request or malformed input."), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Forbidden"}), 403
        return render_template("404.html", error_code=403, error_message="Access denied to requested resource."), 403

    @app.errorhandler(404)
    def not_found_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Resource Not Found"}), 404
        return render_template("404.html", error_code=404, error_message="The requested page or endpoint does not exist."), 404

    @app.errorhandler(413)
    def payload_too_large_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Payload Too Large"}), 413
        return render_template("404.html", error_code=413, error_message="Submitted content exceeds the maximum size limit."), 413

    @app.errorhandler(500)
    def internal_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal Server Error"}), 500
        return render_template("404.html", error_code=500, error_message="An internal server error occurred."), 500

    # -------------------------------------------------------------
    # CLI COMMANDS
    # -------------------------------------------------------------

    @app.cli.command("init-db")
    def init_db_cmd():
        """Initializes database schema."""
        db.create_all()
        print("[+] Database tables created successfully.")

    @app.cli.command("train-ml")
    def train_ml_cmd():
        """Trains machine learning spam model."""
        train_spam_classifier()

    @app.cli.command("create-admin")
    def create_admin_cmd():
        """Creates a default administrator account for academic defense demo."""
        db.create_all()
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", email="admin@mailshield.local", role="admin")
            admin.set_password("Admin@12345")
            db.session.add(admin)
            db.session.commit()
            print("[+] Created admin user: admin / Admin@12345")
        else:
            print("[*] Admin user already exists.")

    return app


if __name__ == "__main__":
    app = create_app("development")
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
