from app import app, db

columns = [
    "ALTER TABLE users ADD COLUMN google_email VARCHAR(200)",
    "ALTER TABLE users ADD COLUMN google_id VARCHAR(200)",
    "ALTER TABLE users ADD COLUMN google_drive_folder VARCHAR(200)",
    "ALTER TABLE users ADD COLUMN google_access_token TEXT",
    "ALTER TABLE users ADD COLUMN google_refresh_token TEXT"
]

with app.app_context():

    for sql in columns:
        try:
            db.session.execute(db.text(sql))
            print("Added:", sql)
        except Exception as e:
            print(e)

    db.session.commit()

print("Database Updated Successfully")