from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from database.db import db
from database.models import User, Analysis
from audit.logger import log_audit_event

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration with credential validation."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation checks
        if not username or len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return render_template("register.html", username=username, email=email)

        if not email or "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email)

        if not password or len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        # Check existing username / email
        if User.query.filter_by(username=username).first():
            flash("That username is already taken. Please choose another.", "warning")
            return render_template("register.html", username=username, email=email)

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "warning")
            return render_template("register.html", username=username, email=email)

        # Create user
        try:
            user = User(username=username, email=email, role="user")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            log_audit_event("USER_REGISTER", f"User registered: {username}", user_id=user.id)
            flash("Registration successful! You can now log in to MailShield.", "success")
            return redirect(url_for("auth.login"))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred during registration: {str(e)}", "danger")

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handles user authentication with secure password verification."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()  # can be username or email
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        if not identifier or not password:
            flash("Please provide both username/email and password.", "warning")
            return render_template("login.html", identifier=identifier)

        # Query by username or email
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            log_audit_event("USER_LOGIN", f"User logged in: {user.username}", user_id=user.id)
            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            log_audit_event("LOGIN_FAILED", f"Failed login attempt for identifier: {identifier}")
            flash("Invalid username/email or password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    """Terminates active session and logs audit event."""
    username = current_user.username
    user_id = current_user.id
    logout_user()
    log_audit_event("USER_LOGOUT", f"User logged out: {username}", user_id=user_id)
    flash("You have been logged out safely.", "info")
    return redirect(url_for("auth.login"))
