# Arkheion — Personal Document Vault

## User Demonstration Guide

Arkheion is a personal document-management and digital-vault application for securely organizing, storing, searching, previewing, downloading, and managing important documents.

> **Important:** This guide is for normal user demonstration. It does not claim that any Internet-connected application is 100% secure.

---

## 1. Getting Started

Open the Arkheion website in a supported modern browser.

The login page provides:

- Username
- Password
- Unlock Vault / Login
- Forgot Password

Enter your registered credentials and select **Unlock Vault**.

After successful authentication, you will be taken to the **Dashboard**.

---

## 2. Dashboard

The dashboard is the main document-management area.

Depending on the configured version, it can provide:

- Total document count
- Recycle Bin count
- Storage usage
- Upcoming document expiries
- Document search
- Category filtering
- Document status filtering
- Sorting
- Google Drive connection status
- Upload and document-management actions

---

## 3. Upload a Document

1. Select **Upload Document**.
2. Choose a document from your computer.
3. Select the appropriate category.
4. Enter an expiry date if applicable.
5. Submit the upload.
6. Confirm that the document appears in the dashboard.

Recommended filenames:

```text
Passport.pdf
Driving_License.pdf
Insurance_2026.pdf
Education_Certificate.pdf
Property_Document.pdf
```

For demonstrations, use dummy/sample documents rather than real sensitive records.

---

## 4. Search Documents

Use the dashboard search field to search by document filename or category.

Examples:

```text
passport
insurance
certificate
property
```

The document list will be filtered according to the search.

---

## 5. Filter and Sort Documents

Documents can be filtered by category and status.

Typical status options include:

- Available
- Trash
- Missing / Deleted

Typical sorting options include:

- Latest
- Oldest
- Name
- Expiry

---

## 6. Preview and Download

### Preview

Select **Preview** to inspect a supported document without downloading it.

### Download

Select **Download** to retrieve the document.

After downloading sensitive documents, avoid leaving them on shared or public computers.

---

## 7. Document Expiry

Enter accurate expiry dates for documents such as:

- Passport
- Driving licence
- Insurance
- Certificate
- Permit
- Contract

The dashboard can show documents whose expiry is approaching.

Do not enter approximate dates.

---

## 8. Recycle Bin

A normal delete operation can move a document to the **Recycle Bin**.

Typical workflow:

```text
Document
   ↓
Delete
   ↓
Recycle Bin
   ↓
Restore OR Permanent Delete
```

### Restore

1. Open **Recycle Bin**.
2. Select the document.
3. Choose **Restore**.
4. Confirm the operation.
5. Verify that the document returns to the normal document list.

### Permanent Delete

Use permanent deletion carefully. Confirm the correct document before proceeding.

Where Google Drive integration is enabled, the corresponding Drive deletion behavior depends on the application's configured workflow.

---

## 9. Google Drive Connection

Arkheion can connect to a user's Google Drive.

1. Open **Cloud Storage** or the Google Drive section of the dashboard.
2. Select **Connect Google Drive**.
3. Complete Google authentication.
4. Review the requested permissions.
5. Grant the required Drive permission.
6. Return to Arkheion.
7. Confirm that the status changes to **Connected**.

If Drive permission is not granted, the application cannot perform the configured Drive operations.

The configured application-managed folder is:

```text
Personal DigiLocker
```

---

## 10. If Google Drive Shows "Not Connected"

Try:

1. Log in again.
2. Open **Cloud Storage**.
3. Select **Connect Google Drive**.
4. Complete Google authorization again.
5. Make sure the required Drive permission is granted.
6. Return to the dashboard.
7. Verify the connection status.

If authorization was revoked from the Google account, reconnect the account.

Do not share Google passwords, OAuth tokens, or refresh tokens with support personnel.

---

## 11. User Profile

The profile/account area may provide:

- View profile
- Edit profile
- Change password
- Account information

Verify changes after saving.

---

## 12. Change Password

1. Open the profile/account area.
2. Select **Change Password**.
3. Enter the requested credentials.
4. Enter the new password.
5. Confirm the new password.
6. Submit.

Use a unique password that is not reused on other services.

---

## 13. Forgot Password

If password recovery is enabled:

1. Select **Forgot Password**.
2. Enter the requested account information.
3. Follow the recovery instructions.
4. Create a new strong password.
5. Log in again.

Never provide your existing password to another person.

---

## 14. Security Features

The application has been configured with security controls including:

- CSRF protection
- Content Security Policy
- Security response headers
- `X-Content-Type-Options`
- `X-Frame-Options`
- Referrer Policy
- Permissions Policy
- HTTP-only session cookies
- SameSite session cookies
- Authentication-protected dashboard
- Google OAuth integration
- Encrypted document-storage workflow

Security depends on application code, deployment configuration, dependencies, credentials, encryption-key management, cloud configuration, and user behavior.

**Do not describe the application as impossible to hack or 100% secure.**

---

## 15. Safe User Practices

Users should:

- Keep passwords private.
- Use a strong, unique password.
- Connect only trusted Google accounts.
- Review Google permissions carefully.
- Keep document expiry dates accurate.
- Review the Recycle Bin periodically.
- Log out on shared computers.
- Keep browsers and operating systems updated.
- Maintain appropriate backups of critical documents.

Never share:

- Passwords
- Session cookies
- CSRF tokens
- Google OAuth access tokens
- Google refresh tokens
- Encryption keys
- API secrets

---

## 16. Administrator Functions

Administrator features are intended only for authorized administrators.

Depending on the configured version, administrative functionality may include:

- User management
- Security/audit logs
- Backup management
- Security monitoring
- Administrative dashboard

Do not provide administrator credentials to normal users.

---

## 17. Recommended Demonstration Flow

Use this sequence for a live demonstration:

```text
1. Open Arkheion
       ↓
2. Login
       ↓
3. Show Dashboard
       ↓
4. Upload sample document
       ↓
5. Select category
       ↓
6. Set expiry date
       ↓
7. Show document in dashboard
       ↓
8. Search document
       ↓
9. Filter / sort
       ↓
10. Preview document
       ↓
11. Download document
       ↓
12. Connect Google Drive
       ↓
13. Show Connected status
       ↓
14. Demonstrate cloud-storage workflow
       ↓
15. Delete sample document
       ↓
16. Open Recycle Bin
       ↓
17. Restore document
       ↓
18. Demonstrate permanent-delete workflow
       ↓
19. Logout
```

---

## 18. Recommended Demo Data

Do not use real:

- Aadhaar documents
- Passports
- Bank statements
- Medical records
- Passwords
- Private certificates
- Other sensitive personal records

Use dummy demonstration files such as:

```text
Demo_Passport.pdf
Demo_Insurance.pdf
Demo_Certificate.pdf
Demo_Property.pdf
Demo_Invoice.pdf
```

---

## 19. Troubleshooting

### Login does not work

Check:

- Username
- Password
- Account status
- Browser cookies
- Application status

Refresh the login page and try again.

### Dashboard does not load

Check:

- Application/server status
- Network connectivity
- Browser Console
- Application logs

### Dashboard appears without styling

Open browser DevTools → **Network** and check CSS/JavaScript requests. Static resources should normally return HTTP `200`.

### Google Drive connection fails

Check:

- Google authorization
- Drive permission
- OAuth consent
- Browser pop-up restrictions
- Application logs
- Whether access was previously revoked

### Upload fails

Check:

- User login status
- File size
- Supported file type
- Google Drive connection if required
- Available storage
- Application logs

---

## 20. Production Readiness Checklist

Before public launch, verify:

- [ ] HTTPS enabled
- [ ] Flask debug mode disabled
- [ ] Production WSGI server configured
- [ ] Strong secret keys stored outside source code
- [ ] OAuth secrets protected
- [ ] Google refresh tokens protected
- [ ] Encryption keys protected
- [ ] Database protected
- [ ] File-upload validation enabled
- [ ] File-size limits enabled
- [ ] CSRF tested on state-changing forms
- [ ] Authorization/IDOR testing completed
- [ ] Login rate limiting tested
- [ ] Password reset security tested
- [ ] Session security tested
- [ ] Admin authorization tested
- [ ] Error pages do not expose stack traces
- [ ] Backups tested
- [ ] Restore procedure tested
- [ ] Google OAuth revocation/reconnection tested
- [ ] Security logging tested
- [ ] Dependencies reviewed
- [ ] Appropriate security/penetration testing completed

---

## 21. Quick Reference

| Function | Location |
|---|---|
| Login | Login page |
| Dashboard | Dashboard |
| Upload | Upload Document |
| Search | Dashboard |
| Category Filter | Dashboard |
| Preview | Document actions |
| Download | Document actions |
| Recycle Bin | Recycle Bin |
| Restore | Recycle Bin |
| Permanent Delete | Recycle Bin |
| Google Drive | Cloud Storage / Dashboard |
| Profile | Profile |
| Change Password | Profile / Account |
| Forgot Password | Login page |
| Administration | Admin area |

---

## 22. Support Information

When reporting a problem, provide:

- What you were trying to do
- Page where the problem occurred
- Exact error message
- Approximate time
- Browser name/version
- Screenshot when appropriate

Never send passwords, session cookies, CSRF tokens, OAuth tokens, refresh tokens, encryption keys, or API secrets.

---

## Arkheion

**Personal Document Vault**

*User Demonstration Guide*

# Installation & Deployment Procedure

This section describes how to install Arkheion on a Windows PC for local use and for the current Cloudflare Tunnel deployment model.

## 1. System Requirements

Recommended environment:

- Windows 10/11 64-bit
- Python 3.11.x
- Internet connection
- Google account if Google Drive backup is required
- Cloudflare account and domain if public HTTPS access is required
- Git (optional, if installing from a Git repository)

> **Important:** Use the same Python environment consistently. Do not mix packages from different Python installations.

## 2. Obtain the Project

Copy or extract the Arkheion project to a local folder, for example:

```text
G:\Cloud Documents\OneDrive\Cloud Document
```

The project should contain the Flask application and its supporting folders/files, such as:

```text
Cloud Document/
├── app.py
├── templates/
├── static/
├── client_secret.json          # required for Google OAuth if used
├── instance/                   # database/config data may be stored here
└── ...
```

The exact files may vary with the project version.

## 3. Install Python

Install Python 3.11.x for Windows.

During installation, enable:

```text
Add Python to PATH
```

Verify:

```cmd
python --version
```

Expected:

```text
Python 3.11.x
```

Also verify pip:

```cmd
python -m pip --version
```

## 4. Create a Virtual Environment

Open Command Prompt in the Arkheion project folder:

```cmd
cd /d "G:\Cloud Documents\OneDrive\Cloud Document"
```

Create the virtual environment:

```cmd
python -m venv .venv
```

Activate it:

```cmd
.venv\Scripts\activate
```

After activation, the command prompt should show something similar to:

```text
(.venv) G:\Cloud Documents\OneDrive\Cloud Document>
```

Upgrade pip:

```cmd
python -m pip install --upgrade pip
```

## 5. Install Python Dependencies

If the project contains `requirements.txt`, install the dependencies with:

```cmd
python -m pip install -r requirements.txt
```

If there is no requirements file, install the dependencies required by the current project version. Typical Arkheion dependencies include Flask, SQLAlchemy, Flask-WTF/CSRF protection, Flask-Talisman, Google authentication libraries, Google API client libraries, and the project's other explicitly imported packages.

After installation, verify the environment:

```cmd
python -m pip list
```

> **Do not blindly downgrade `cryptography`, PyOpenSSL, or other security packages to solve an import error.** If the current project reports a PyDrive2/oauth2client/OpenSSL compatibility error, first record the installed versions and then repair the dependency chain deliberately.

Useful diagnostic commands:

```cmd
python -m pip show pyOpenSSL
python -m pip show cryptography
python -m pip show oauth2client
python -m pip show PyDrive2
```

## 6. Configure the Application

Before starting the application, review the configuration in `app.py` and the project's configuration/environment files.

Do not hard-code production passwords, API keys, OAuth secrets, encryption keys, or email passwords in source code.

Where supported, use environment variables.

For example, from Command Prompt:

```cmd
set SECRET_KEY=your-long-random-secret
```

For permanent Windows environment variables, use Windows Environment Variables rather than committing secrets to Git.

## 7. Configure Google Drive (Optional)

Google Drive integration requires a Google Cloud OAuth client configuration.

Place the OAuth client file expected by the current application in the project directory:

```text
client_secret.json
```

The current application uses:

```python
Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=SCOPES
)
```

Therefore the file must be available from the application's working directory unless the application is changed to use another path.

### Google Cloud configuration

Configure an OAuth 2.0 Client ID in Google Cloud Console and add the exact redirect URI generated by the application.

For local testing, this will normally be similar to:

```text
http://127.0.0.1:5000/google/callback
```

For the public Arkheion deployment, use the exact HTTPS callback URL generated by the production deployment.

Do not guess the redirect URI. It must exactly match the URI configured in Google Cloud.

After configuration:

1. Start Arkheion.
2. Log in.
3. Open the dashboard.
4. Select **Connect Google Drive**.
5. Sign in to Google.
6. Approve the requested Drive permission.
7. Return to Arkheion.
8. Confirm the dashboard shows Google Drive as connected.

If Google Drive access was previously revoked, reconnect and approve the required permission again.

## 8. Initialize / Verify the Database

Start the application once so that its database initialization code can run.

Then verify that the expected SQLite/database files and tables are created.

Do not delete an existing production database merely to solve a startup or migration problem.

Before changing database structure, make a backup.

## 9. Start Arkheion Locally

With the virtual environment activated:

```cmd
cd /d "G:\Cloud Documents\OneDrive\Cloud Document"
.venv\Scripts\activate
python app.py
```

The Flask application should listen on the configured local port, currently expected to be:

```text
http://127.0.0.1:5000
```

Open a browser and test the application locally before exposing it through Cloudflare.

## 10. First-Time Functional Test

Perform these tests in order:

### Authentication

- Open the login page.
- Log in with a valid user.
- Confirm the dashboard opens.
- Log out.
- Confirm protected pages cannot be accessed without authentication.

### CSRF

For development verification, a POST request without a CSRF token should be rejected.

Do not disable CSRF protection just to make a form work.

Every state-changing HTML POST form should contain the appropriate CSRF token.

### Documents

Test:

1. Upload a document.
2. Confirm it appears on the dashboard.
3. Search for it.
4. Filter/sort it.
5. Preview it if supported.
6. Download it.
7. Move it to Recycle Bin.
8. Restore it.
9. Test permanent deletion only after confirming the backup/recovery behavior.

### Google Drive

If enabled:

1. Connect Google Drive.
2. Confirm the correct Google account is shown.
3. Upload a test document.
4. Confirm the expected Drive behavior.
5. Revoke access from the Google account.
6. Reconnect and verify the application's connection status.

## 11. Run Arkheion with Cloudflare Tunnel

The current deployment uses Cloudflare Tunnel to expose the local Flask application through HTTPS.

Current tunnel configuration:

```yaml
tunnel: cd4cd539-a756-47e8-b2fa-d93c978b1eea

credentials-file: C:\Users\DB02-DESIGN01\.cloudflared\cd4cd539-a756-47e8-b2fa-d93c978b1eea.json

ingress:
  - hostname: arkheion.in
    service: http://localhost:5000

  - hostname: www.arkheion.in
    service: http://localhost:5000

  - service: http_status:404
```

The configuration file is located at:

```text
C:\Users\DB02-DESIGN01\.cloudflared\config.yml
```

Validate it:

```cmd
cloudflared tunnel ingress validate
```

Start the tunnel:

```cmd
cloudflared tunnel run arkheion
```

The Flask application must already be running on port 5000.

Then access:

```text
https://arkheion.in
```

The Cloudflare Tunnel and DNS route must be configured before the public hostname will work.

## 12. Recommended Startup Order

For the current Windows deployment, use this order:

### Command Prompt 1 — Flask

```cmd
cd /d "G:\Cloud Documents\OneDrive\Cloud Document"
.venv\Scripts\activate
python app.py
```

Keep this window running.

### Command Prompt 2 — Cloudflare Tunnel

```cmd
cd /d C:\Cloudflare
cloudflared tunnel run arkheion
```

Keep this window running.

Then open:

```text
https://arkheion.in
```

## 13. Production Configuration

Before allowing real users to use the application:

- Disable Flask debug mode.
- Do not use the Flask development server as the final production WSGI server.
- Use HTTPS.
- Set secure session cookie settings for HTTPS:
  - `SESSION_COOKIE_SECURE=True`
  - `SESSION_COOKIE_HTTPONLY=True`
  - `SESSION_COOKIE_SAMESITE="Lax"`
- Keep CSRF protection enabled.
- Keep security headers/CSP enabled and test them after every frontend change.
- Store secrets outside source code.
- Rotate any credential that has previously been exposed.
- Use strong password hashing.
- Add login/rate-limit protection against brute-force attempts.
- Verify authorization for every document/user/admin operation.
- Validate uploaded files by type, size, filename, and storage handling.
- Keep database and encrypted-file backups.
- Test restoration from backup.
- Keep dependencies updated and review security advisories.
- Do not expose development error pages or stack traces to users.

## 14. Backup Before Updating

Before updating Arkheion:

1. Stop Flask.
2. Stop Cloudflare Tunnel if required.
3. Back up the database.
4. Back up uploaded/encrypted files.
5. Back up required configuration.
6. Record the current application version.
7. Apply the update.
8. Test login, upload, download, Google Drive, and recycle-bin functions.
9. Restore the previous version if a critical regression is found.

Never treat the application folder alone as a complete backup if user data is stored elsewhere.

## 15. Troubleshooting

### `python` is not recognized

Verify Python installation:

```cmd
where python
python --version
```

Use the Python installation intended for Arkheion.

### Virtual environment is not active

Run:

```cmd
.venv\Scripts\activate
```

Then:

```cmd
where python
```

The first result should point to the project's `.venv`.

### Flask does not start

Run:

```cmd
python app.py
```

Read the first traceback from the bottom upward and identify the first application/dependency error.

For Google-related dependency errors, record:

```cmd
python -m pip show pyOpenSSL
python -m pip show cryptography
python -m pip show oauth2client
python -m pip show PyDrive2
```

Do not randomly install/downgrade packages.

### Port 5000 is already in use

Check:

```cmd
netstat -ano | findstr :5000
```

Identify the process and stop it only if it is safe to do so.

### Google OAuth redirect error

Check:

- Google Cloud OAuth client type.
- Authorized redirect URI.
- Application-generated callback URL.
- `client_secret.json`.
- Domain/HTTPS configuration for public deployment.

The redirect URI must match exactly.

### Google Drive says not connected

Check:

- Google permission was granted.
- The correct Google account was used.
- The refresh token exists.
- The Drive folder ID exists.
- Google access was not revoked.
- Application logs for the Google API error.

### Cloudflare shows an error

Check the Flask application first:

```text
http://127.0.0.1:5000
```

Then check the tunnel:

```cmd
cloudflared tunnel run arkheion
```

Then validate:

```cmd
cloudflared tunnel ingress validate
```

If local Flask is down, Cloudflare Tunnel cannot successfully proxy requests to port 5000.

## 16. Suggested Installation Checklist

```text
[ ] Install Python 3.11.x
[ ] Copy Arkheion project
[ ] Create .venv
[ ] Activate .venv
[ ] Upgrade pip
[ ] Install requirements.txt
[ ] Configure environment variables/secrets
[ ] Configure client_secret.json if Google Drive is used
[ ] Configure Google OAuth redirect URI
[ ] Start Flask
[ ] Verify local login
[ ] Verify CSRF
[ ] Verify upload/download
[ ] Verify recycle bin
[ ] Verify Google Drive
[ ] Disable debug for production
[ ] Configure secure session cookies
[ ] Validate Cloudflare Tunnel
[ ] Start Cloudflare Tunnel
[ ] Test https://arkheion.in
[ ] Create/verify backups
[ ] Perform final security checks
```

## 17. Important Deployment Note

The current Arkheion setup is a **Windows-hosted Flask application behind Cloudflare Tunnel**. Cloudflare provides the public HTTPS/tunnel layer; it does not replace the Flask application server, database, application security, backups, or Windows host security.

For a long-term production deployment, consider moving the application to a dedicated server/cloud VM or managed hosting environment with a production WSGI server, process supervision, automated backups, monitoring, and a controlled deployment process.
