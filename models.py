from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(20),default="user")
    
    email = db.Column(db.String(150))
    full_name = db.Column(db.String(150))
    mobile = db.Column(db.String(20))
    is_active = db.Column(db.Boolean,default=True)
    failed_attempts = db.Column(db.Integer,default=0)
    is_locked = db.Column(db.Boolean,default=False)
    reset_token = db.Column(db.String(100))
    reset_expiry = db.Column(db.DateTime)
    otp = db.Column(db.String(10))
    otp_expiry = db.Column(db.DateTime)
    # FIX (security): counts failed OTP verification attempts, so a 6-digit
    # OTP (1,000,000 possible values) can't just be brute-forced within its
    # 5-minute validity window. Reset to 0 whenever a fresh OTP is issued.
    otp_attempts = db.Column(db.Integer, default=0)
    google_email = db.Column(db.String(150))
    google_id = db.Column(db.String(100))
    google_drive_folder = db.Column(db.String(200))
    google_access_token = db.Column(db.Text)
    google_refresh_token = db.Column(db.Text)
    created_on = db.Column(db.DateTime,default=datetime.utcnow)


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    category = db.Column(db.String(100))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime,nullable=True)
    google_file_id = db.Column(db.String(200))
    expiry_date = db.Column(db.Date)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    is_deleted = db.Column(db.Boolean, default=False)

    # FIX: previously the dashboard's "Storage Used" total was computed by
    # calling os.path.getsize() on the local uploads/ copy of each file —
    # but upload_document() deletes that local copy right after pushing it
    # to Drive, so the check almost always found nothing and reported 0.
    # Storing the size here (captured at upload time, before the local file
    # is removed) makes the total independent of local filesystem state.
    file_size = db.Column(db.BigInteger, default=0)

    # Tracks the file's *actual*, actively-verified state on Google Drive,
    # as opposed to google_file_id which only tells us whether we ever had
    # one — it never gets cleared just because someone deleted the file
    # directly in the Drive UI. One of "sync" (present, not trashed),
    # "trash" (present, in Drive's Trash), or "deleted" (permanently gone /
    # 404 from Drive, including files purged after 30 days in Trash).
    # Existing rows default to "sync"; app.py verifies and corrects this
    # opportunistically (see check_drive_file_status()).
    drive_status = db.Column(db.String(20), default="sync")


class AuditLog(db.Model):

    __tablename__ = "audit_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        nullable=False
    )

    username = db.Column(
        db.String(100)
    )

    action = db.Column(
        db.String(50),
        nullable=False
    )

    document_name = db.Column(
        db.String(300)
    )

    created_on = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )
    
class SecurityLog(db.Model):

    __tablename__ = "security_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100)
    )

    ip_address = db.Column(
        db.String(50)
    )

    action = db.Column(
        db.String(50)
    )

    status = db.Column(
        db.String(20)
    )

    created_on = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )
    
class LoginHistory(db.Model):

    __tablename__ = "login_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100)
    )

    login_time = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    logout_time = db.Column(
        db.DateTime
    )

    ip_address = db.Column(
        db.String(50)
    )

    status = db.Column(
        db.String(20)
    )
