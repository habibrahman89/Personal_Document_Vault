from app import app, db

with app.app_context():

    try:
        db.session.execute(
            db.text(
                "ALTER TABLE users ADD COLUMN otp VARCHAR(10)"
            )
        )
        print("otp added")
    except Exception as e:
        print(e)

    try:
        db.session.execute(
            db.text(
                "ALTER TABLE users ADD COLUMN otp_expiry DATETIME"
            )
        )
        print("otp_expiry added")
    except Exception as e:
        print(e)

    db.session.commit()

print("DONE")