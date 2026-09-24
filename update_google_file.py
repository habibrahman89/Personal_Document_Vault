from app import app, db

with app.app_context():

    try:

        db.session.execute(
            db.text(
                """
                ALTER TABLE documents
                ADD COLUMN google_file_id VARCHAR(200)
                """
            )
        )

        db.session.commit()

        print("Column Added")

    except Exception as e:

        print(e)