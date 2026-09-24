from app import app, db

with app.app_context():
    db.session.execute(
        db.text(
            "ALTER TABLE users ADD COLUMN otp_expiry DATETIME"
        )
    )
    db.session.commit()

print("otp_expiry added")