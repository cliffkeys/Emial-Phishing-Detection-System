import os
from app import create_app
from database.db import db
from database.models import User

env = os.getenv("FLASK_ENV") or ("production" if os.getenv("VERCEL") else "development")
app = create_app(env)

with app.app_context():
    try:
        db.create_all()
        # Ensure default admin exists for immediate academic demo/login
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin", email="admin@mailshield.local", role="admin")
            admin.set_password("Admin@12345")
            db.session.add(admin)
            db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass

if __name__ == "__main__":
    app.run()
