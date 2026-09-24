from app import app
from models import db

with app.app_context():

    result = db.session.execute(
        db.text(
            "PRAGMA table_info(users)"
        )
    ).fetchall()

    print(result)