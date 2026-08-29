import os
from app import create_app
from database.db import db

env = os.getenv("FLASK_ENV", "production")
app = create_app(env)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()
