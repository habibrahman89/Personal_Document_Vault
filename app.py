from flask import (
    Flask, render_template, request, redirect, session,
    send_from_directory, flash, send_file, url_for, jsonify
)
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
from cryptography.fernet import Fernet
from sqlalchemy import or_
from encryption import encrypt_file, decrypt_file
from zoneinfo import ZoneInfo
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from flask_mail import Mail, Message
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

import os
import io
import mimetypes
import json
import gc
import time
import shutil
import tempfile
import zipfile
import random

# FIX (deployment): detect "am I running on a real host, over HTTPS" in a
# way that isn't tied to one specific platform. RENDER is set automatically
# by Render; RAILWAY_ENVIRONMENT is set automatically by Railway. APP_ENV is
# a manual fallback you can set yourself on any other platform.
IS_PRODUCTION = bool(
    os.environ.get("RENDER") or
    os.environ.get("RAILWAY_ENVIRONMENT") or
    os.environ.get("APP_ENV") == "production"
)

# OAUTHLIB_INSECURE_TRANSPORT tells the OAuth library it's OK to complete the
# flow over plain HTTP. That's needed for local dev (http://127.0.0.1:5000)
# but must NEVER be set in production, since that would be a real security
# regression once the app is served over HTTPS.
if not IS_PRODUCTION:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# FIX: Google's consent screen lets a user uncheck individual permissions —
# "Drive access" is a separate checkbox from basic profile/email. If they
# decline it, Google's token exchange legitimately returns a smaller scope
# set than what was requested. By default oauthlib treats that as a hard
# error and raises, which crashed the whole /google/callback route with a
# raw 500 for a completely normal user choice. This tells oauthlib to
# accept the mismatch instead of raising; google_callback() below then
# explicitly checks what was actually granted and handles a missing Drive
# scope gracefully rather than assuming it's always present.
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

IST = ZoneInfo("Asia/Kolkata")
IST_OFFSET = timedelta(hours=5, minutes=30)

# Google Drive OAuth Scopes
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/drive.file"
]

# FIX (deployment): client_secret.json should NOT be committed to Git (it's
# a secret). On Render, upload it as a "Secret File" at this same relative
# path, OR set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET as plain env vars and
# skip the file entirely. Both paths are supported below.
if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
    GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
elif os.path.exists("client_secret.json"):
    with open("client_secret.json", "r") as f:
        google_config = json.load(f)["web"]
    GOOGLE_CLIENT_ID = google_config["client_id"]
    GOOGLE_CLIENT_SECRET = google_config["client_secret"]
else:
    raise RuntimeError(
        "Google OAuth credentials not found. Set GOOGLE_CLIENT_ID and "
        "GOOGLE_CLIENT_SECRET env vars, or provide client_secret.json."
    )

print("CLIENT ID :", GOOGLE_CLIENT_ID[:25] + "...")
print("CLIENT SECRET :", GOOGLE_CLIENT_SECRET[:8] + "...")

from models import LoginHistory, db, User, Document, AuditLog, SecurityLog

app = Flask(__name__)

csrf = CSRFProtect(app)

# NOTE (security): these were hardcoded in the original file. Prefer setting
# real secrets via environment variables in production; the hardcoded values
# are kept here only as a fallback so the app still runs out of the box.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'test@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'test')

mail = Mail(app)

app.permanent_session_lifetime = timedelta(minutes=15)
app.secret_key = os.environ.get('SECRET_KEY', 'personal_digilocker_secret_key')

# FIX (security): session cookie hardening.
# - HTTPONLY: JavaScript can't read the session cookie at all — blocks a
#   whole class of session-theft via XSS, even if some other XSS bug were
#   ever introduced.
# - SAMESITE=Lax: the cookie isn't sent on cross-site requests triggered by
#   another site (a big part of defense-in-depth against CSRF, though it's
#   not a substitute for real CSRF tokens on state-changing routes — see
#   the CSRF note elsewhere).
# - SECURE: only sent over HTTPS. Only enabled in production (IS_PRODUCTION)
#   since it would silently break login when testing locally over plain
#   http://127.0.0.1.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION

# FIX (security): caps request size to prevent a very large upload from
# exhausting memory or disk. This matters more now that preview/download
# read the whole decrypted file into memory (see cleanup_temp_files()) —
# an unbounded upload is a real memory-exhaustion DoS vector, not just a
# disk one. 50 MB comfortably covers PDF/JPG/PNG/DOCX personal documents;
# raise it if you expect larger files (e.g. scanned multi-page PDFs).
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# FIX (deployment): Render's free web service has NO persistent disk — the
# filesystem is wiped on every deploy/restart, which would silently erase
# this SQLite file (and every user/document/log in it). Set a DATABASE_URL
# env var pointing at a real Postgres instance (Render Postgres, Neon,
# Supabase, etc.) in production; SQLite remains the default for local dev.
database_url = os.environ.get("DATABASE_URL")

if database_url:
    # Render/most providers hand out "postgres://"; SQLAlchemy needs
    # "postgresql://".
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = \
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "database.db")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

print("\n========== DATABASE ==========")
print(app.config["SQLALCHEMY_DATABASE_URI"])
print("==============================\n")

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# FIX: these folders were used throughout the app but never guaranteed to
# exist, causing FileNotFoundError on a fresh checkout / clean deploy.
# NOTE: on Render's free tier these folders are scratch space only — they're
# wiped on every deploy/restart. That's fine here because the app already
# treats them as temporary (files are encrypted, pushed to Google Drive,
# then deleted locally), but don't rely on anything in them persisting.
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs("temp", exist_ok=True)
os.makedirs("backups/database", exist_ok=True)
os.makedirs("backups/uploads", exist_ok=True)

db.init_app(app)

# FIX: adds new columns to an EXISTING database without requiring a
# migration framework (Alembic/Flask-Migrate aren't set up in this
# project). db.create_all() only creates missing tables — it never alters
# an existing table's columns — so a plain SQLite/Postgres install from
# before this change would otherwise crash the first time any code
# reads/writes these fields. Safe to run on every startup: each ALTER is a
# no-op once its column already exists.
with app.app_context():
    inspector = db.inspect(db.engine)
    if "documents" in inspector.get_table_names():
        existing_columns = [c["name"] for c in inspector.get_columns("documents")]

        if "drive_status" not in existing_columns:
            with db.engine.connect() as conn:
                conn.execute(db.text(
                    "ALTER TABLE documents ADD COLUMN drive_status VARCHAR(20) DEFAULT 'sync'"
                ))
                conn.commit()
            print("Migration: added documents.drive_status column")

        if "file_size" not in existing_columns:
            with db.engine.connect() as conn:
                conn.execute(db.text(
                    "ALTER TABLE documents ADD COLUMN file_size BIGINT DEFAULT 0"
                ))
                conn.commit()
            print("Migration: added documents.file_size column")

    if "users" in inspector.get_table_names():
        existing_user_columns = [c["name"] for c in inspector.get_columns("users")]

        if "otp_attempts" not in existing_user_columns:
            with db.engine.connect() as conn:
                conn.execute(db.text(
                    "ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0"
                ))
                conn.commit()
            print("Migration: added users.otp_attempts column")

# FIX (deployment): Render (like most PaaS platforms) terminates HTTPS at a
# reverse proxy in front of your app, then forwards requests to your app
# over plain HTTP internally, setting X-Forwarded-Proto: https. Without
# ProxyFix, Flask doesn't know the original request was HTTPS, so
# url_for(..., _external=True) in google_login()/google_callback() would
# generate an http:// redirect_uri — which won't match the https:// URI you
# register in Google Cloud Console, and the OAuth flow will fail.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def create_log(action, document_name=None):

    log = AuditLog(
        user_id=session["user_id"],
        username=session["username"],
        action=action,
        document_name=document_name
    )

    db.session.add(log)
    db.session.commit()


def create_security_log(username, action, status):

    print("SECURITY LOG:", username, action, status)

    log = SecurityLog(
        username=username,
        ip_address=request.remote_addr,
        action=action,
        status=status
    )

    db.session.add(log)
    db.session.commit()

    print("SECURITY SAVED")


def get_google_service(user):

    credentials = Credentials(
        token=user.google_access_token,
        refresh_token=user.google_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )

    service = build("drive", "v3", credentials=credentials)

    return service


# ---------------------------------------------------
# GOOGLE DRIVE DOWNLOAD
# ---------------------------------------------------

def download_from_google_drive(service, file_id, save_path):

    drive_request = service.files().get_media(fileId=file_id)

    with open(save_path, "wb") as fh:

        downloader = MediaIoBaseDownload(fh, drive_request)

        done = False

        while not done:
            status, done = downloader.next_chunk()
            if status:
                print(f"Downloading... {int(status.progress() * 100)}%")

    print("Google Drive Download Completed")


def cleanup_temp_files(*paths, retries=3, delay=0.3):
    """
    Best-effort immediate deletion of temp files, with a couple of short
    retries. On Windows, a file can still be briefly locked (by the OS, an
    AV scanner, or a not-yet-released handle) right when we try to delete
    it, so a single attempt silently failing was the root cause of temp/
    filling up with orphaned files. This doesn't guarantee deletion (see
    sweep_stale_temp_files for the safety net), but it clears the vast
    majority of cases immediately instead of leaving everything behind.
    """
    gc.collect()

    for path in paths:
        for attempt in range(retries):
            try:
                if os.path.exists(path):
                    os.remove(path)
                break
            except PermissionError:
                time.sleep(delay)
            except Exception as e:
                print(f"Cleanup error for {path}:", e)
                break


def is_drive_file_not_found(e):
    """
    True if the exception is Google Drive telling us the file itself is
    gone (HTTP 404) — as opposed to a network hiccup, auth error, etc. Used
    to detect the "DB record survived (e.g. via /restore) but the actual
    Drive file was already permanently removed" case, so we can degrade
    gracefully instead of showing a raw exception.
    """
    error_str = str(e)
    return "404" in error_str or "File not found" in error_str


def check_drive_file_status(service, google_file_id):
    """
    Actively asks Google Drive for the real, current state of a file —
    this is the only way to detect that someone deleted or trashed it
    directly in the Drive UI, since that never notifies the app on its own.
    Also returns the file's size, so documents uploaded before the
    file_size column existed can be backfilled opportunistically whenever
    they're checked, instead of needing a one-off migration script.

    Returns a dict: {"status": ..., "size": int | None}
      status "sync"    - file exists and is not in Drive's Trash
      status "trash"   - file exists but is in Drive's Trash (recoverable)
      status "deleted" - file is permanently gone (404 — hard-deleted, or
                         purged from Trash after Google's retention window)
      status "unknown" - the check itself failed for an unrelated reason
                         (network, auth, rate limit, etc.) — callers should
                         NOT overwrite an existing status based on
                         "unknown", since it doesn't tell us anything about
                         the file itself. size is always None in this case.
    """
    try:
        meta = service.files().get(fileId=google_file_id, fields="id,trashed,size").execute()
        status = "trash" if meta.get("trashed") else "sync"
        size = int(meta["size"]) if meta.get("size") is not None else None
        return {"status": status, "size": size}
    except Exception as e:
        if is_drive_file_not_found(e):
            return {"status": "deleted", "size": None}
        print("Drive status check error:", e)
        return {"status": "unknown", "size": None}


def sweep_stale_temp_files(folder="temp", max_age_seconds=600):
    """
    Safety net: on every preview/download request, remove any file in the
    temp folder older than max_age_seconds. This guarantees temp/ doesn't
    grow unbounded even if a specific request's immediate cleanup failed
    (crash mid-request, browser aborted the download, file still locked
    after all retries, server restarted before cleanup ran, etc.).
    """
    try:
        now = time.time()
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            try:
                if os.path.isfile(path) and (now - os.path.getmtime(path)) > max_age_seconds:
                    os.remove(path)
            except Exception as e:
                print(f"Stale temp sweep error for {path}:", e)
    except Exception as e:
        print("Stale temp sweep error:", e)


@app.before_request
def session_timeout():

    session.permanent = True

    if "user_id" in session:
        session.modified = True


@app.teardown_request
def rollback_on_error(exception=None):
    """
    Safety net: if a request raised an unhandled exception, roll back the
    DB session before it's returned to the pool for the next request. This
    isn't a fix for any specific bug — it's a guard against the general
    class of problem where one failed request (e.g. a transient SQLite
    "database is locked" error under rapid-fire requests) leaves a broken
    transaction that then causes unrelated, hard-to-diagnose failures on
    the *next* request.
    """
    if exception is not None:
        db.session.rollback()


@app.after_request
def set_security_headers(response):
    """
    FIX (security): baseline security headers on every response.
    - X-Content-Type-Options: stops the browser from guessing content types
      and executing e.g. an uploaded file as HTML/JS if it were ever served
      without an explicit type.
    - X-Frame-Options: prevents the app from being embedded in an <iframe>
      on another site (clickjacking — e.g. an attacker overlaying invisible
      "Delete"/"Permanent Delete" buttons over what looks like a harmless
      page). SAMEORIGIN still allows this app's own /preview/<id> iframe
      use, which is same-origin.
    - Referrer-Policy: avoids leaking full URLs (which can contain doc IDs)
      to third-party sites via the Referer header on outbound links.
    - Strict-Transport-Security: only sent in production (over HTTPS) —
      tells browsers to always use HTTPS for this domain going forward,
      closing the window for a downgrade/sslstrip-style attack.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


def backup_database():
    shutil.copy("instance/database.db", "backups/database/database.db")


def backup_uploads():
    shutil.copytree("uploads", "backups/files", dirs_exist_ok=True)


def create_backup():

    try:
        os.makedirs("backups/database", exist_ok=True)
        os.makedirs("backups/uploads", exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ==========================
        # Backup SQLite Database
        # ==========================
        source_db = os.path.join("instance", "database.db")
        db_backup = os.path.join("backups", "database", f"database_{timestamp}.db")

        if os.path.exists(source_db):
            shutil.copy2(source_db, db_backup)
        else:
            print("Database file not found:", source_db)

        # ==========================
        # Backup Encrypted Uploads
        # ==========================
        zip_name = os.path.join("backups", "uploads", f"uploads_{timestamp}.zip")

        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as backup:
            for root, dirs, files in os.walk(app.config["UPLOAD_FOLDER"]):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, app.config["UPLOAD_FOLDER"])
                    backup.write(file_path, arcname)

        print(f"Backup created successfully: {timestamp}")
        return True

    except Exception as e:
        print("Backup Error:", e)
        return False


def _require_admin():
    """Helper: returns a redirect/response if the current user isn't an
    authenticated admin, otherwise returns None."""
    if "user_id" not in session:
        return redirect("/")
    if session.get("role") != "admin":
        return "Unauthorized", 403
    return None


# FIX: /backup and /restore previously only checked "is logged in", so any
# regular user could trigger a full database/upload restore. Restricted to admins.
@app.route("/backup")
def backup():

    denied = _require_admin()
    if denied:
        return denied

    success = create_backup()

    if success:
        create_log("BACKUP", "LOCAL_BACKUP")
        print("Backup completed.")
    else:
        print("Backup failed.")

    return redirect("/dashboard")


@app.route("/restore")
def restore_backup():

    denied = _require_admin()
    if denied:
        return denied

    try:
        db_folder = "backups/database"
        db_files = sorted(os.listdir(db_folder), reverse=True)

        if db_files:
            latest_db = os.path.join(db_folder, db_files[0])
            shutil.copy2(latest_db, "instance/database.db")

        upload_folder = "backups/uploads"
        zip_files = sorted(os.listdir(upload_folder), reverse=True)

        if zip_files:
            latest_zip = os.path.join(upload_folder, zip_files[0])

            shutil.rmtree(app.config["UPLOAD_FOLDER"], ignore_errors=True)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            with zipfile.ZipFile(latest_zip, "r") as backup:
                backup.extractall(app.config["UPLOAD_FOLDER"])

        create_log("RESTORE", "LOCAL_BACKUP")
        flash("Backup restored successfully.", "success")
        print("Backup restored successfully.")

    except Exception as e:
        print("Restore Error:", e)
        flash(f"Restore failed: {e}", "danger")

    return redirect("/dashboard")


# -----------------------------
# HOME PAGE
# -----------------------------
@app.route("/")
def home():

    if "user_id" in session:
        return redirect("/dashboard")

    return render_template("login.html")


# -----------------------------
# REGISTER
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        full_name = request.form["full_name"].strip()
        mobile = request.form["mobile"].strip()
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists")
            return redirect("/register")

        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            mobile=mobile,
            password=hashed_password,
            role="user",
            is_active=True,
            failed_attempts=0,
            is_locked=False
        )

        db.session.add(new_user)
        db.session.commit()

        create_security_log(username, "REGISTER", "SUCCESS")

        flash("Registration Successful")

        return redirect("/")

    return render_template("register.html")

# -----------------------------
# USERNAME AVAILABILITY CHECK (AJAX)
# -----------------------------
@app.route("/api/check-username")
def check_username():

    username = request.args.get("username", "").strip()

    if not username:
        return jsonify({"available": False, "message": "Username is required."})

    if len(username) < 3:
        return jsonify({"available": False, "message": "Username must be at least 3 characters."})

    # Keep this in sync with whatever characters /register ultimately accepts.
    if not all(c.isalnum() or c in "._-" for c in username):
        return jsonify({"available": False, "message": "Only letters, numbers, '.', '_' and '-' are allowed."})

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({"available": False, "message": "This username is already taken."})

    return jsonify({"available": True, "message": "Username is available."})


# -----------------------------
# GOOGLE LOGIN
# -----------------------------
@app.route("/google/login")
def google_login():

    # FIX: previously this route could be hit while logged out, and the
    # callback would then crash on session["user_id"].
    if "user_id" not in session:
        return redirect("/")

    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES
    )

    flow.redirect_uri = url_for("google_callback", _external=True)

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    session["state"] = state
    session["code_verifier"] = flow.code_verifier

    return redirect(authorization_url)


# -----------------------------
# CALLBACK
# -----------------------------
@app.route("/google/callback")
def google_callback():

    # FIX: guard against a stale/forged callback hit without an active
    # session or without a prior /google/login call.
    if "user_id" not in session:
        return redirect("/")

    if "state" not in session or "code_verifier" not in session:
        flash("Google login session expired. Please try again.", "danger")
        return redirect("/dashboard")

    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        state=session["state"]
    )

    flow.redirect_uri = url_for("google_callback", _external=True)
    flow.code_verifier = session["code_verifier"]

    # FIX: the whole exchange is now wrapped in try/except. Previously any
    # failure here — including the very common case of a user declining a
    # permission on Google's consent screen (see below) — surfaced as a raw
    # 500 debugger page and dropped the user out of the sign-up flow
    # entirely.
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        service = build("oauth2", "v2", credentials=credentials)
        userinfo = service.userinfo().get().execute()
    except Exception as e:
        print("Google OAuth token exchange failed:", e)
        flash(
            "Google sign-in didn't complete. Please try connecting Google "
            "Drive again.",
            "danger"
        )
        return redirect("/dashboard")

    # FIX: Google's consent screen lets a user uncheck individual
    # permissions — Drive access is a separate checkbox from basic
    # profile/email. If it wasn't granted, credentials.scopes won't include
    # the drive.file scope even though the sign-in itself succeeded. Trying
    # to use the Drive API in that case would fail with an insufficient-
    # permission error, so check explicitly and stop before that happens.
    granted_scopes = credentials.scopes or []
    drive_scope = "https://www.googleapis.com/auth/drive.file"

    if drive_scope not in granted_scopes:
        flash(
            "Google sign-in succeeded, but Drive access wasn't granted, so "
            "documents can't be backed up yet. Click \"Connect Google "
            "Drive\" again and make sure to approve Drive access on the "
            "consent screen.",
            "warning"
        )
        return redirect("/dashboard")

    # FIX (security): never log full OAuth tokens. credentials.token and
    # credentials.refresh_token are standing credentials to this user's
    # Google Drive folder — logging them in full means anyone with log
    # access (hosting dashboard, log aggregator, misconfigured public log
    # endpoint) gets ongoing access to that user's documents. Truncated
    # previews are enough to confirm the flow worked without exposing the
    # usable secret.
    print("Google account connected:", userinfo.get("email"))

    user = db.session.get(User, session["user_id"])

    user.google_email = userinfo["email"]
    user.google_id = userinfo["id"]
    user.google_access_token = credentials.token
    user.google_refresh_token = credentials.refresh_token

    db.session.commit()

    print("Google Drive tokens saved for:", user.google_email)

    # -----------------------------
    # CONNECT TO GOOGLE DRIVE
    # -----------------------------
    try:
        drive_service = build("drive", "v3", credentials=credentials)

        results = drive_service.files().list(
            q="mimeType='application/vnd.google-apps.folder' and name='Personal DigiLocker' and trashed=false",
            spaces="drive",
            fields="files(id,name)"
        ).execute()

        folders = results.get("files", [])

        if folders:
            folder_id = folders[0]["id"]
            print("Folder already exists")
        else:
            folder_metadata = {
                "name": "Personal DigiLocker",
                "mimeType": "application/vnd.google-apps.folder"
            }
            folder = drive_service.files().create(
                body=folder_metadata,
                fields="id"
            ).execute()
            folder_id = folder["id"]
            print("New Folder Created")

        print("Folder ID :", folder_id)

        user.google_drive_folder = folder_id
        db.session.commit()

        print("==============================")
        print("GOOGLE DRIVE CONNECTED")
        print("Email :", user.google_email)
        print("Folder:", folder_id)
        print("==============================")

        flash("Google Drive connected successfully.", "success")

    except Exception as e:
        # The Google account IS linked (tokens saved above) even if folder
        # setup failed here — don't lose that. Just surface a clear message
        # instead of crashing; the user can retry, and get_google_service()
        # will pick up the saved tokens next time.
        print("Google Drive folder setup failed:", e)
        flash(
            "Google account connected, but setting up your Drive folder "
            "failed. Please try connecting again.",
            "danger"
        )

    return redirect("/dashboard")


# -----------------------------
# LOGIN
# -----------------------------
@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    if not username or not password:
        flash("Username and Password required")
        return redirect("/")

    print("\n========== LOGIN ==========")
    print("USERNAME:", username)

    user = User.query.filter_by(username=username).first()

    print("USER:", user)

    if user:
        print("ROLE:", user.role)

    if user and user.is_locked:
        create_security_log(username, "ACCOUNT_LOCKED", "FAILED")
        flash("Account Locked. Contact Administrator.")
        return redirect("/")

    # SUCCESS LOGIN
    if user and check_password_hash(user.password, password):

        if not user.is_active:
            create_security_log(username, "LOGIN_BLOCKED", "FAILED")
            flash("Account Disabled")
            return redirect("/")

        user.failed_attempts = 0
        db.session.commit()

        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        old_sessions = LoginHistory.query.filter_by(
            username=user.username,
            logout_time=None
        ).all()

        for s in old_sessions:
            s.logout_time = datetime.now(IST)

        db.session.commit()

        history = LoginHistory(
            username=user.username,
            login_time=datetime.now(IST),
            ip_address=request.remote_addr,
            status="SUCCESS"
        )

        db.session.add(history)
        db.session.commit()

        session["login_history_id"] = history.id

        create_log("LOGIN")
        create_security_log(username, "LOGIN", "SUCCESS")

        return redirect("/dashboard")

    # FAILED LOGIN
    create_security_log(username, "FAILED_LOGIN", "FAILED")

    if user:
        user.failed_attempts += 1

        if user.failed_attempts >= 3:
            user.is_locked = True
            create_security_log(username, "ACCOUNT_LOCKED", "FAILED")

        db.session.commit()

    flash("Invalid Username or Password")

    return redirect("/")


# -----------------------------
# FORGOT PASSWORD
# -----------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        username = request.form["username"]

        user = User.query.filter_by(username=username).first()

        if user:

            otp = str(random.randint(100000, 999999))

            user.otp = otp

            # FIX: SQLite's DateTime column strips tzinfo on read-back (and a
            # plain, non-timezone-aware Postgres column would too), so a
            # value stored as tz-aware comes back naive later and blows up
            # when compared against a tz-aware "now". Store/compare
            # consistently as naive IST wall-clock time instead — see the
            # same pattern in reset_password() and verify_otp().
            user.otp_expiry = datetime.now(IST).replace(tzinfo=None) + timedelta(minutes=5)

            # FIX (security): reset the brute-force attempt counter every
            # time a fresh OTP is issued, so a new OTP always gets its own
            # full allowance of guesses.
            user.otp_attempts = 0

            db.session.commit()

            msg = Message(
                "Password Reset OTP",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user.email]
            )

            msg.body = f"""
            Hello {user.username},

            Your Personal DigiLocker OTP is:

            {otp}

            This OTP is valid for 5 minutes.

            Regards,
            Personal DigiLocker
            """

            mail.send(msg)

            print("\n========== OTP ==========")
            print("USER :", user.username)
            print("EMAIL:", user.email)
            print("OTP  :", otp)
            print("=========================")

            session["reset_user"] = user.id

            return redirect("/reset-password")

        flash("User not found")
        return redirect("/forgot-password")

    return render_template("forgot_password.html")


# -----------------------------
# RESET PASSWORD
# -----------------------------
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if "reset_user" not in session:
        return redirect("/forgot-password")

    if request.method == "POST":

        otp = request.form["otp"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        user = User.query.filter_by(otp=otp).first()

        if not user:
            flash("Invalid OTP")
            return redirect("/reset-password")

        # FIX: otp_expiry is stored as naive IST wall-clock time (see
        # forgot_password()), so compare against naive "now" too — comparing
        # naive vs. tz-aware raises TypeError.
        if not user.otp_expiry or user.otp_expiry < datetime.now(IST).replace(tzinfo=None):
            flash("OTP Expired")
            return redirect("/forgot-password")

        if password != confirm:
            flash("Passwords do not match")
            return redirect("/reset-password")

        user.password = generate_password_hash(password)

        user.otp = None
        user.otp_expiry = None

        user.failed_attempts = 0
        user.is_locked = False

        db.session.commit()

        session.pop("reset_user", None)

        flash("Password Reset Successful")

        return redirect("/")

    return render_template("reset_password.html")


# -----------------------------
# VERIFY OTP
# -----------------------------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    MAX_OTP_ATTEMPTS = 5

    if request.method == "POST":

        username = request.form["username"]
        otp = request.form["otp"]

        # FIX (security): look up the user by username alone (not
        # username+otp together) so we can track/limit guesses even when
        # they're wrong — the previous version had no way to do that, since
        # a wrong guess just returned no user at all.
        user = User.query.filter_by(username=username).first()

        if (
            user
            and user.otp
            and user.otp_expiry
            and user.otp_expiry > datetime.now(IST).replace(tzinfo=None)
        ):

            if user.otp_attempts >= MAX_OTP_ATTEMPTS:
                # Too many wrong guesses — invalidate this OTP entirely
                # rather than continue to allow attempts against it. A 6-digit
                # OTP (1,000,000 possibilities) is brute-forceable well within
                # its 5-minute validity window without a limit like this.
                user.otp = None
                user.otp_expiry = None
                db.session.commit()
                flash("Too many incorrect attempts. Please request a new OTP.")
                return render_template("verify_otp.html")

            if user.otp == otp:
                user.otp_attempts = 0
                db.session.commit()
                session["reset_user"] = user.id
                return redirect("/reset-password")

            user.otp_attempts += 1
            db.session.commit()

        # Deliberately the same generic message whether the username
        # doesn't exist, the OTP expired, or the OTP was just wrong — avoids
        # leaking which case it was.
        flash("Invalid OTP")

    return render_template("verify_otp.html")


# -----------------------------
# TEST MAIL
# -----------------------------
@app.route("/test-mail")
def test_mail():

    try:
        msg = Message(
            "Test Email",
            sender=app.config["MAIL_USERNAME"],
            recipients=["habib408@gmail.com"]
        )

        msg.body = "This is a test email from Personal DigiLocker."

        mail.send(msg)

        # FIX: the original code referenced an undefined `user` variable
        # here, which raised a NameError on every call to this route.
        print("\n========== EMAIL SENT ==========")
        print("TO :", app.config["MAIL_USERNAME"])

        if "username" in session:
            create_security_log(session["username"], "OTP_SENT", "SUCCESS")

        print("===============================\n")

        flash("Test email sent.")

        return "EMAIL SENT"

    except Exception as e:
        return str(e)


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/")

    search_text = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()
    status = request.args.get("status", "").strip()
    sort = request.args.get("sort", "latest").strip()

    print("\n========== DASHBOARD ==========")
    print("USER ID :", session["user_id"])
    print("SEARCH  :", search_text)

    query = Document.query.filter(
        Document.user_id == session["user_id"],
        Document.is_deleted == False
    )

    if search_text:
        query = query.filter(
            or_(
                Document.filename.ilike(f"%{search_text}%"),
                Document.category.ilike(f"%{search_text}%")
            )
        )

    if category:
        query = query.filter(Document.category == category)

    # FIX: filter on the actively-verified drive_status column (three
    # states: sync/trash/deleted) instead of the old binary
    # google_file_id-is-null check, matching the updated Status dropdown.
    # A null google_file_id is treated as "deleted" too, covering rows from
    # before this column existed that haven't been refreshed yet.
    if status == "available":
        query = query.filter(
            Document.drive_status == "sync",
            Document.google_file_id.isnot(None)
        )
    elif status == "trash":
        query = query.filter(Document.drive_status == "trash")
    elif status == "missing":
        query = query.filter(
            or_(
                Document.drive_status == "deleted",
                Document.google_file_id.is_(None)
            )
        )

    if sort == "latest":
        query = query.order_by(Document.upload_date.desc())
    elif sort == "oldest":
        query = query.order_by(Document.upload_date.asc())
    elif sort == "name":
        query = query.order_by(Document.filename.asc())
    elif sort == "expiry":
        query = query.order_by(Document.expiry_date.asc())

    documents = query.all()

    categories = (
        db.session.query(Document.category)
        .filter(
            Document.user_id == session["user_id"],
            Document.is_deleted == False
        )
        .distinct()
        .order_by(Document.category)
        .all()
    )

    categories = [c[0] for c in categories if c[0]]

    print("RESULTS :", len(documents))
    for doc in documents:
        print(doc.id, doc.filename)

    today = date.today()

    upcoming = Document.query.filter(
        Document.user_id == session["user_id"],
        Document.is_deleted == False,
        Document.expiry_date != None,
        Document.expiry_date >= today,
        Document.expiry_date <= today + timedelta(days=30)
    ).order_by(Document.expiry_date).all()

    deleted_count = Document.query.filter_by(
        user_id=session["user_id"],
        is_deleted=True
    ).count()

    total_docs = Document.query.filter_by(
        user_id=session["user_id"],
        is_deleted=False
    ).count()

    # -----------------------------
    # Storage calculation (ALL documents)
    # -----------------------------
    # FIX: this used to call os.path.getsize() on the local uploads/ copy of
    # each file — but upload_document() deletes that local copy right after
    # pushing it to Drive, so this almost always found nothing and reported
    # 0.0 MB regardless of how much was actually stored. file_size is
    # captured at upload time (before the local file is deleted) and
    # backfilled opportunistically for older documents whenever they're
    # viewed or refreshed (see check_drive_file_status()), so this sum is
    # now independent of local filesystem state.
    total_size = db.session.query(
        db.func.coalesce(db.func.sum(Document.file_size), 0)
    ).filter_by(
        user_id=session["user_id"],
        is_deleted=False
    ).scalar()

    storage_mb = round(total_size / (1024 * 1024), 2)

    search_count = len(documents)

    print("TOTAL DOCS :", total_docs)
    print("RECYCLE    :", deleted_count)
    print("STORAGE MB :", storage_mb)
    print("===============================\n")

    user = db.session.get(
        User,
        session["user_id"]
    )

    google_connected = False

    try:

        if (
            user.google_email
            and user.google_refresh_token
            and user.google_drive_folder
        ):

            service = get_google_service(user)

            # Verify Google Drive connection
            service.about().get(
                fields="user"
            ).execute()

            google_connected = True

    except Exception as e:

        print("Google Drive verification failed:", e)

        error = str(e)

        if (
            "invalid_grant" in error
            or "invalid_token" in error
            or "unauthorized" in error
        ):

            user.google_email = None
            user.google_refresh_token = None
            user.google_drive_folder = None

            db.session.commit()

            google_connected = False

        else:
            # Temporary network/API issue.
            # Keep the saved connection.
            google_connected = True

    return render_template(
        "dashboard.html",
        username=session["username"],
        user=user,
        documents=documents,
        google_connected=google_connected,
        total_docs=total_docs,
        deleted_count=deleted_count,
        today=date.today(),
        storage_mb=storage_mb,
        upcoming=upcoming,
        search_count=search_count,
        search=search_text,
        category=category,
        status=status,
        sort=sort,
        categories=categories
    )


# -----------------------------
# ADMIN
# -----------------------------
@app.route("/admin")
def admin():

    # FIX: auth/role check now happens before any DB queries run
    # (previously several queries executed even for unauthenticated users).
    denied = _require_admin()
    if denied:
        return denied

    user = db.session.get(User, session["user_id"])

    today_logins = LoginHistory.query.filter_by(status="SUCCESS").count()
    locked_users = User.query.filter_by(is_locked=True).count()
    active_sessions = LoginHistory.query.filter_by(logout_time=None).count()
    inactive_users = User.query.filter_by(is_active=False).count()

    total_users = User.query.count()
    total_documents = Document.query.count()
    total_logs = AuditLog.query.count()
    deleted_documents = Document.query.filter_by(is_deleted=True).count()
    total_security = SecurityLog.query.count()

    users = User.query.order_by(User.id.desc()).all()
    documents = Document.query.order_by(Document.id.desc()).limit(20).all()
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(20).all()

    return render_template(
        "admin.html",
        user=user,
        total_users=total_users,
        total_documents=total_documents,
        total_logs=total_logs,
        total_security_logs=total_security,
        today_logins=today_logins,
        locked_users=locked_users,
        active_sessions=active_sessions,
        inactive_users=inactive_users,
        logs=logs,
        deleted_documents=deleted_documents,
        users=users,
        documents=documents,
    )


# -----------------------------
# ADMIN USERS
# -----------------------------
@app.route("/admin/users")
def admin_users():

    denied = _require_admin()
    if denied:
        return denied

    users = User.query.order_by(User.id.desc()).all()

    return render_template("admin_users.html", users=users)


@app.route("/admin/user/delete/<int:user_id>")
def delete_user(user_id):

    denied = _require_admin()
    if denied:
        return denied

    user = db.session.get(User, user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        create_log("DELETE_USER", user.username)

    return redirect("/admin/users")


@app.route("/admin/user/edit/<int:user_id>", methods=["GET", "POST"])
def admin_edit_user(user_id):

    denied = _require_admin()
    if denied:
        return denied

    user = db.session.get(User, user_id)

    if not user:
        return redirect("/admin/users")

    if request.method == "POST":

        user.username = request.form["username"]
        user.email = request.form["email"]
        user.mobile = request.form["mobile"]
        user.role = request.form["role"]

        user.is_active = bool(request.form.get("active"))

        db.session.commit()

        create_log("EDIT_USER", user.username)

        flash("User updated successfully")

        return redirect("/admin/users")

    return render_template("edit_user.html", user=user)


@app.route("/admin/login-history")
def admin_login_history():

    denied = _require_admin()
    if denied:
        return denied

    history = LoginHistory.query.order_by(LoginHistory.login_time.desc()).all()

    return render_template("login_history.html", history=history)


@app.route("/admin/user/status/<int:user_id>")
def user_status(user_id):

    denied = _require_admin()
    if denied:
        return denied

    user = db.session.get(User, user_id)

    if user:
        user.is_active = not user.is_active
        db.session.commit()
        create_log("USER_STATUS", user.username)

    return redirect("/admin/users")


@app.route("/admin/unlock/<int:user_id>")
def unlock_user(user_id):

    denied = _require_admin()
    if denied:
        return denied

    user = db.session.get(User, user_id)

    if user:
        user.is_locked = False
        user.failed_attempts = 0
        db.session.commit()
        create_log("UNLOCK_USER", user.username)

    return redirect("/admin/users")


# -----------------------------
# ADMIN AUDIT VIEWER
# -----------------------------
@app.route("/admin/audit")
def admin_audit():

    denied = _require_admin()
    if denied:
        return denied

    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()

    return render_template("admin_audit.html", logs=logs)


# -----------------------------
# ADMIN BACKUPS
# -----------------------------
@app.route("/admin/backups")
def admin_backups():

    denied = _require_admin()
    if denied:
        return denied

    database_backups = []
    uploads_backups = []

    db_folder = "backups/database"
    if os.path.exists(db_folder):
        database_backups = sorted(os.listdir(db_folder), reverse=True)

    upload_folder = "backups/uploads"
    if os.path.exists(upload_folder):
        uploads_backups = sorted(os.listdir(upload_folder), reverse=True)

    return render_template(
        "admin_backups.html",
        database_backups=database_backups,
        uploads_backups=uploads_backups
    )


# FIX: these two routes previously had NO auth check at all, and took
# `folder`/`filename` straight from the URL, allowing an unauthenticated
# path-traversal read or delete of arbitrary files (e.g. "../../instance/database.db").
# Now: admin-only, folder is restricted to a whitelist, filename is sanitized.
_ALLOWED_BACKUP_FOLDERS = {"database", "uploads"}


@app.route("/backup/download/<folder>/<filename>")
def download_backup(folder, filename):

    denied = _require_admin()
    if denied:
        return denied

    if folder not in _ALLOWED_BACKUP_FOLDERS:
        return "Invalid folder", 400

    safe_filename = secure_filename(filename)
    path = os.path.join("backups", folder, safe_filename)

    if not os.path.isfile(path):
        return "File not found", 404

    return send_file(path, as_attachment=True)


@app.route("/backup/delete/<folder>/<filename>")
def delete_backup(folder, filename):

    denied = _require_admin()
    if denied:
        return denied

    if folder not in _ALLOWED_BACKUP_FOLDERS:
        return "Invalid folder", 400

    safe_filename = secure_filename(filename)
    path = os.path.join("backups", folder, safe_filename)

    if os.path.exists(path):
        os.remove(path)
        create_log("DELETE_BACKUP", safe_filename)

    return redirect("/admin/backups")


# -----------------------------
# ADMIN SECURITY
# -----------------------------
@app.route("/admin/security")
def admin_security():

    denied = _require_admin()
    if denied:
        return denied

    logs = SecurityLog.query.order_by(SecurityLog.id.desc()).all()

    return render_template("admin_security.html", logs=logs)


# -----------------------------
# CHANGE PASSWORD
# -----------------------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":

        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        user = db.session.get(User, session["user_id"])

        if not check_password_hash(user.password, old_password):
            return """
            <h3>Old password is incorrect</h3>
            <a href='/change-password'>Back</a>
            """

        if new_password != confirm_password:
            return """
            <h3>New passwords do not match</h3>
            <a href='/change-password'>Back</a>
            """

        user.password = generate_password_hash(new_password)

        db.session.commit()

        return redirect("/dashboard")

    return render_template("change_password.html")


@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(User, session["user_id"])

    return render_template("profile.html", user=user)


@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(User, session["user_id"])

    if not user.created_on:
        user.created_on = datetime.now(IST)
        db.session.commit()

    if request.method == "POST":

        user.full_name = request.form["full_name"]
        user.email = request.form["email"]
        user.mobile = request.form["mobile"]

        db.session.commit()

        return redirect("/profile")

    return render_template("edit_profile.html", user=user)

# -----------------------------
# CLOUD STORAGE
# -----------------------------
@app.route("/cloud-storage")
def cloud_storage():

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(
        User,
        session["user_id"]
    )

    google_connected = False

    if (
        user.google_email
        and user.google_refresh_token
        and user.google_drive_folder
    ):

        try:

            service = get_google_service(user)

            # Verify token
            service.about().get(
                fields="user"
            ).execute()

            # Verify folder still exists
            service.files().get(
                fileId=user.google_drive_folder,
                fields="id,name"
            ).execute()

            google_connected = True

        except Exception as e:

            print("Google verification failed:", e)

            error = str(e)

            if (
                "invalid_grant" in error
                or "invalid_token" in error
                or "unauthorized" in error
                or "File not found" in error
                or "404" in error
            ):

                user.google_email = None
                user.google_refresh_token = None
                user.google_drive_folder = None

                db.session.commit()

                google_connected = False

    return render_template(
        "cloud_storage.html",
        user=user,
        google_connected=google_connected
    )
    
# -----------------------------
# CLOUD STORAGE
# -----------------------------
@app.route("/google/disconnect")
def google_disconnect():

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(
        User,
        session["user_id"]
    )

    user.google_email = None
    user.google_refresh_token = None
    user.google_drive_folder = None

    db.session.commit()

    flash(
        "Google Drive disconnected successfully.",
        "success"
    )

    return redirect("/cloud-storage")

# -----------------------------
# LOGOUT
# -----------------------------
@app.route("/logout")
def logout():

    history = db.session.get(LoginHistory, session.get("login_history_id"))

    if history:
        history.logout_time = datetime.now(IST)
        db.session.commit()

    if "username" in session:
        create_security_log(session["username"], "LOGOUT", "SUCCESS")
        create_log("LOGOUT")

    session.clear()

    return redirect("/")


@app.errorhandler(413)
def handle_file_too_large(e):
    """Friendly response for uploads exceeding MAX_CONTENT_LENGTH, instead
    of the default Flask/Werkzeug error page."""
    flash("That file is too large. Maximum upload size is 50 MB.", "danger")
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/")


@app.route("/upload", methods=["POST"])
def upload_document():
    """
    Design:  Encrypt -> Upload to Google Drive -> Delete local temporary files.
    """

    if "user_id" not in session:
        return redirect("/")

    file = request.files.get("document")

    if not file or not file.filename:
        flash("No file selected", "danger")
        return redirect("/dashboard")

    user = db.session.get(User, session["user_id"])

    if (
        not user.google_email or
        not user.google_refresh_token or
        not user.google_drive_folder
    ):
        flash(
            "Google Drive is not connected. Please connect your Google Drive account before uploading documents.",
            "warning"
        )
        return redirect("/dashboard")

    original_filename = secure_filename(file.filename)

    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], original_filename)
    encrypted_path = temp_path + ".enc"

    try:
        # ---------------- ENCRYPT ----------------
        file.save(temp_path)
        encrypt_file(temp_path, encrypted_path)

        # FIX: capture the size now, while the encrypted file still exists
        # locally — this is what the dashboard's "Storage Used" total reads
        # from now, instead of re-checking the local filesystem later (which
        # doesn't work once this file is deleted below). This is also the
        # actual encrypted size that lands on Drive, so it matches what's
        # really consuming storage quota.
        file_size = os.path.getsize(encrypted_path)

        # ---------------- UPLOAD TO GOOGLE DRIVE ----------------
        service = get_google_service(user)

        drive_filename = original_filename + ".enc"

        media = MediaFileUpload(encrypted_path, resumable=True)

        uploaded = service.files().create(
            body={
                "name": drive_filename,
                "parents": [user.google_drive_folder]
            },
            media_body=media,
            fields="id"
        ).execute()

        del media

        print("Uploaded Successfully")
        print(uploaded["id"])

        category = request.form["category"]

        expiry_date = request.form.get("expiry_date")

        if expiry_date:
            expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d").date()
        else:
            expiry_date = None

        doc = Document(
            filename=drive_filename,
            category=category,
            expiry_date=expiry_date,
            google_file_id=uploaded["id"],
            user_id=session["user_id"],
            is_deleted=False,
            file_size=file_size
        )

        db.session.add(doc)
        db.session.commit()

        create_log("UPLOAD", drive_filename)

    except Exception as e:
        print("Upload Error:", e)
        flash(f"Upload failed: {e}", "danger")
        return redirect("/dashboard")

    finally:
        # ---------------- DELETE LOCAL TEMPORARY FILES ----------------
        gc.collect()
        time.sleep(1)

        for path in (temp_path, encrypted_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except PermissionError:
                print(f"Temporary file {path} is still locked. Keeping it for now.")
            except Exception as e:
                print(e)

    return redirect("/dashboard")


@app.route("/download/<int:id>")
def download_document(id):
    """
    Design:  Download encrypted file -> Decrypt -> Download -> Clean up.
    """

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(User, session["user_id"])

    document = db.session.get(Document, id)

    if document is None:
        flash("Document not found")
        return redirect("/dashboard")

    if document.user_id != user.id:
        flash("Access denied")
        return redirect("/dashboard")

    if not document.google_file_id:
        flash("Google Drive file missing")
        return redirect("/dashboard")

    service = get_google_service(user)

    # ---------------- SWEEP OLD LEFTOVERS ----------------
    # Safety net: catches anything a previous request's cleanup missed.
    sweep_stale_temp_files()

    original_name = document.filename.replace(".enc", "")
    ext = os.path.splitext(original_name)[1]

    # FIX: use unique temp filenames (mkstemp) instead of names derived from
    # document.filename, so concurrent downloads of the same document can't
    # collide/overwrite each other's temp files.
    fd_enc, temp_enc = tempfile.mkstemp(suffix=".enc", dir="temp")
    os.close(fd_enc)

    fd_dec, temp_original = tempfile.mkstemp(suffix=ext, dir="temp")
    os.close(fd_dec)

    try:
        # ---------------- DOWNLOAD ENCRYPTED FILE ----------------
        print("Downloading from Google Drive...")
        download_from_google_drive(service, document.google_file_id, temp_enc)

        # ---------------- DECRYPT ----------------
        print("Decrypting...")
        decrypt_file(temp_enc, temp_original)

        document.last_accessed = datetime.now(IST)
        db.session.commit()

        # ---------------- READ INTO MEMORY, THEN CLEAN UP IMMEDIATELY ----------------
        # FIX: previously the temp files were only deleted once the HTTP
        # response closed (call_on_close). For an inline preview the browser
        # can hold that connection open for as long as the tab is showing
        # the file, and even for attachment downloads the close event isn't
        # always reliable across browsers. Reading the bytes into memory and
        # deleting the temp files right here means cleanup no longer depends
        # on the response's lifecycle at all — the files are gone before we
        # even start sending data to the client.
        with open(temp_original, "rb") as f:
            file_bytes = f.read()

        cleanup_temp_files(temp_enc, temp_original)

        print("Returning file...")

        # ---------------- DOWNLOAD (send to user) ----------------
        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=True,
            download_name=original_name
        )

    except Exception as e:
        cleanup_temp_files(temp_enc, temp_original)
        print("Download Error:", e)

        if is_drive_file_not_found(e):
            # FIX: same case as preview_document() — the DB record survived
            # (often via /restore reverting to an older snapshot) but the
            # file was already permanently removed from Drive. Mark it
            # Deleted instead of leaving it looking "Sync" forever.
            document.google_file_id = None
            document.drive_status = "deleted"
            db.session.commit()
            flash(
                "This file no longer exists on Google Drive (it may have "
                "been permanently deleted after your last backup was "
                "taken). It has been marked as Deleted.",
                "danger"
            )
        else:
            flash(f"Download failed: {e}", "danger")

        return redirect("/dashboard")


@app.route("/delete/<int:doc_id>")
def delete_document(doc_id):
    """
    Soft delete: moves the document to the recycle bin (is_deleted = True).
    The file stays on Google Drive and the DB record stays intact so it can
    be restored later. Use /permanent-delete/<id> to remove it for good.
    """

    if "user_id" not in session:
        return redirect("/")

    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    create_log("DELETE", doc.filename)

    doc.is_deleted = True

    db.session.commit()

    flash("Document moved to Recycle Bin.", "success")

    return redirect("/dashboard")


@app.route("/view/<int:doc_id>")
def view_document(doc_id):

    if "user_id" not in session:
        return redirect("/")

    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    create_log("VIEW", doc.filename)

    preview_file = doc.filename.replace(".enc", "")

    doc.last_accessed = datetime.now(IST)

    # FIX: opening the Document Viewer is exactly the moment a user cares
    # whether the file is actually still there — actively verify against
    # Drive here rather than trusting a status that was only ever set at
    # upload time. This is what catches "deleted directly in the Drive UI"
    # instead of showing a stale "Sync" badge forever.
    if doc.google_file_id:
        user = db.session.get(User, session["user_id"])
        if user.google_email and user.google_refresh_token:
            try:
                service = get_google_service(user)
                result = check_drive_file_status(service, doc.google_file_id)
                if result["status"] != "unknown":
                    doc.drive_status = result["status"]
                    if result["status"] == "deleted":
                        doc.google_file_id = None
                    # Backfill: documents uploaded before file_size existed
                    # (or where it's still 0 for any reason) get it filled
                    # in here for free, since we're already asking Drive.
                    if not doc.file_size and result["size"] is not None:
                        doc.file_size = result["size"]
            except Exception as e:
                print("Drive status check error (view):", e)

    db.session.commit()

    return render_template(
        "view_document.html",
        document=doc,
        preview_file=preview_file
    )


@app.route("/refresh-status/<int:doc_id>")
def refresh_status(doc_id):
    """
    Manual "Refresh Status" action (dashboard row + Document Viewer button).
    Deliberately NOT run automatically for every document on every
    dashboard load — that would mean one Drive API call per document per
    page view, which doesn't scale and burns API quota fast. This lets the
    user pull an up-to-date status for a specific document on demand.
    """

    if "user_id" not in session:
        return redirect("/")

    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    next_url = request.args.get("next") or "/dashboard"

    if not doc.google_file_id:
        # Already marked gone locally — nothing on Drive to check against.
        return redirect(next_url)

    user = db.session.get(User, session["user_id"])

    if not (user.google_email and user.google_refresh_token):
        flash("Connect Google Drive to check document status.", "warning")
        return redirect(next_url)

    try:
        service = get_google_service(user)
        result = check_drive_file_status(service, doc.google_file_id)

        if result["status"] == "unknown":
            flash("Could not check Drive status right now. Try again shortly.", "warning")
        else:
            doc.drive_status = result["status"]
            if result["status"] == "deleted":
                doc.google_file_id = None
            if not doc.file_size and result["size"] is not None:
                doc.file_size = result["size"]
            db.session.commit()

            status_labels = {"sync": "Sync", "trash": "Trash", "deleted": "Deleted"}
            flash(f"Status updated: {status_labels[result['status']]}.", "success")

    except Exception as e:
        print("Drive status check error (manual refresh):", e)
        flash("Could not check Drive status right now. Try again shortly.", "warning")

    return redirect(next_url)


@app.route("/preview/<int:doc_id>")
def preview_document(doc_id):
    """
    Design:  Download encrypted file -> Decrypt -> Preview -> Clean up.
    """

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(User, session["user_id"])

    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    if not doc.google_file_id:

        create_log("VIEW_FAILED", doc.filename)

        return """
        <div style='
            padding:40px;
            font-family:Arial;
            text-align:center;
        '>

            <h2>
                Document Not Found
            </h2>

            <p>
                This document is not available on Google Drive.
            </p>

        </div>
        """

    # ---------------- SWEEP OLD LEFTOVERS ----------------
    # Safety net: catches anything a previous request's cleanup missed.
    sweep_stale_temp_files()

    ext = os.path.splitext(doc.filename.replace(".enc", ""))[1]

    fd_enc, temp_enc = tempfile.mkstemp(suffix=".enc", dir="temp")
    os.close(fd_enc)

    fd_dec, temp_dec = tempfile.mkstemp(suffix=ext, dir="temp")
    os.close(fd_dec)

    try:
        # ---------------- DOWNLOAD ENCRYPTED FILE ----------------
        service = get_google_service(user)
        download_from_google_drive(service, doc.google_file_id, temp_enc)

        # ---------------- DECRYPT ----------------
        decrypt_file(temp_enc, temp_dec)

        doc.last_accessed = datetime.now(IST)
        create_log("VIEW", doc.filename)
        db.session.commit()

        # ---------------- READ INTO MEMORY, THEN CLEAN UP IMMEDIATELY ----------------
        # FIX: previously the temp files were only deleted once the HTTP
        # response closed (call_on_close). For an inline preview, the
        # browser's PDF/image viewer can hold that connection open for as
        # long as the tab stays open, so the temp file sat on disk the whole
        # time — and if the connection never closed cleanly, it never got
        # cleaned up at all. Reading the bytes into memory and deleting the
        # temp files right here means cleanup no longer depends on the
        # response's lifecycle — the files are gone before the response is
        # even created.
        with open(temp_dec, "rb") as f:
            file_bytes = f.read()

        cleanup_temp_files(temp_enc, temp_dec)

        original_name = doc.filename.replace(".enc", "")
        mimetype = mimetypes.guess_type(original_name)[0] or "application/octet-stream"

        # ---------------- PREVIEW ----------------
        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=False,
            download_name=original_name,
            mimetype=mimetype
        )

    except Exception as e:
        cleanup_temp_files(temp_enc, temp_dec)

        create_log("VIEW_FAILED", doc.filename)
        print("Preview Error:", e)

        if is_drive_file_not_found(e):
            # FIX: the DB record survived (often because /restore brought
            # back an older database snapshot) but the file itself was
            # already permanently removed from Google Drive. Mark it
            # Deleted so the dashboard reflects reality instead of
            # repeatedly offering a preview/download that will always fail.
            doc.google_file_id = None
            doc.drive_status = "deleted"
            db.session.commit()

            return """
            <div style='
                padding:40px;
                font-family:Arial;
                text-align:center;
            '>

                <h2>
                    Document Not Found
                </h2>

                <p>
                    This file no longer exists on Google Drive (it may have
                    been permanently deleted after your last backup was
                    taken). It has been marked as Missing.
                </p>

            </div>
            """

        return f"""
        <div style='
            padding:40px;
            font-family:Arial;
            text-align:center;
        '>

            <h2>
                Preview Failed
            </h2>

            <p>
                {e}
            </p>

        </div>
        """


@app.route("/restore/<int:doc_id>")
def restore_document(doc_id):

    if "user_id" not in session:
        return redirect("/")

    doc = Document.query.get_or_404(doc_id)

    # FIX: missing ownership check (same class of bug as delete_document).
    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    create_log("RESTORE", doc.filename)

    doc.is_deleted = False

    db.session.commit()

    return redirect("/recycle-bin")


@app.route("/recycle-bin")
def recycle_bin():

    if "user_id" not in session:
        return redirect("/")

    documents = Document.query.filter_by(
        user_id=session["user_id"],
        is_deleted=True
    ).all()

    total_deleted = len(documents)

    return render_template(
        "recycle_bin.html",
        documents=documents,
        total_deleted=total_deleted
    )


@app.route("/permanent-delete/<int:doc_id>")
def permanent_delete_document(doc_id):
    """
    Design:  Delete from Google Drive -> Delete database record.
    This is the "delete forever" action from the Recycle Bin.
    """

    if "user_id" not in session:
        return redirect("/")

    user = db.session.get(User, session["user_id"])

    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != session["user_id"]:
        return "Unauthorized", 403

    # ---------------- REMOVE FROM GOOGLE DRIVE ----------------
    # NOTE: this moves the file to Drive's own Trash (recoverable there for
    # a grace period, same as deleting a file in the Drive UI) rather than
    # calling files().delete() (an instant, unrecoverable erase). Combined
    # with /restore reverting the *database* to an older snapshot, a hard
    # delete here would create DB rows pointing at files with zero chance of
    # recovery. Trashing keeps that recoverable on Drive's side even if the
    # local DB backup/restore cycle and Drive's actual state drift apart.
    if doc.google_file_id:
        try:
            service = get_google_service(user)
            service.files().update(
                fileId=doc.google_file_id,
                body={"trashed": True}
            ).execute()
        except Exception as e:
            # If the file is already gone from Drive (e.g. 404 — it was
            # already trashed/deleted directly on Drive, or a DB restore
            # brought back a row whose file no longer exists), treat that as
            # success and continue removing the local record; any other
            # error is surfaced so the record isn't silently orphaned.
            if not is_drive_file_not_found(e):
                print("Google Drive delete error:", e)
                flash(f"Could not delete file from Google Drive: {e}", "danger")
                return redirect("/recycle-bin")

    # ---------------- DELETE DATABASE RECORD ----------------
    try:
        create_log("PERMANENT_DELETE", doc.filename)

        db.session.delete(doc)
        db.session.commit()
    except Exception as e:
        # FIX (defensive): if this commit fails for any reason (e.g. SQLite
        # "database is locked" under rapid-fire requests), roll back
        # explicitly so a half-open transaction doesn't get inherited by
        # the next request on this connection. Previously an uncaught
        # failure here surfaced as a raw 500, and — worse — could leave the
        # session in a state where the *next* request also failed
        # unpredictably instead of behaving consistently.
        db.session.rollback()
        print("Permanent delete DB error:", e)
        flash(f"Could not delete document record: {e}", "danger")
        return redirect("/recycle-bin")

    flash("Document permanently deleted.", "success")

    return redirect("/recycle-bin")


@app.route("/audit")
def audit():

    if "user_id" not in session:
        return redirect("/")

    logs = AuditLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(AuditLog.id.desc()).all()

    login_count = AuditLog.query.filter_by(
        user_id=session["user_id"],
        action="LOGIN"
    ).count()

    download_count = AuditLog.query.filter_by(
        user_id=session["user_id"],
        action="DOWNLOAD"
    ).count()

    view_count = AuditLog.query.filter_by(
        user_id=session["user_id"],
        action="VIEW"
    ).count()

    return render_template(
        "audit.html",
        logs=logs,
        login_count=login_count,
        download_count=download_count,
        view_count=view_count,
        ist_offset=IST_OFFSET
    )


# -----------------------------
# RUN APP
# -----------------------------
# NOTE (deployment): On Render/Railway, this block is NOT what actually
# serves traffic — the platform runs your app via the Start Command
# (gunicorn app:app), which is production-grade (multi-worker, no
# debugger). This block only matters when you run `python app.py` locally.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=not IS_PRODUCTION)
