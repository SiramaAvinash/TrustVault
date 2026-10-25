# TrustVault

TrustVault is a local-first secure document-sharing application built with FastAPI, SQLite, and React + Vite. This enhanced starter removes hard-coded demo sign-in values and adds self-registration, optional email-based two-factor authentication, expiring grants, version history, approvals, personalized watermarks, integrity verification, notifications, analytics, and user administration.

## Features

- Self-registration using the user's own email and password; new accounts are **Viewer** by default.
- Optional Google sign-in with server-side ID-token verification; new Google accounts receive Viewer access by default.
- Argon2 password hashing and short-lived JWT access tokens.
- Administrator-managed role promotion/deactivation; users cannot select their own role. Admin role does not automatically expose private document contents.
- Optional email-based 2FA and new-device challenges when the Resend email provider is configured. Google sign-in uses server-verified Google ID tokens.
- Private file storage, upload size/type/signature validation, generated storage names, SHA-256 hashes.
- Server-side authorization for document metadata, downloads, edits, grants, versions, and approvals.
- Granular document grants: read/preview, edit, download-only, or share-only; grants support expiry and immediate revocation.
- Email notifications for grants/revocations, approval decisions, and document version updates (Resend API key required).
- Watermarked downloads for PDF, image, and text files; download endpoint checks the stored file's SHA-256 before serving.
- Document version history and restoration, with snapshots of the replaced current version.
- Optional approval requirement; sharing is blocked until an administrator approves the document.
- Advanced search by title, category, owner, date, file type, permission, hash prefix, and safe allow-listed sorting.
- Dashboard analytics scoped to the signed-in user's access; administrators see global metrics.
- Audit events with actor email, outcome, resource, notification status, and hash-chain verification; denied document actions alert the owner by email when Resend is configured (same user/action/document alerts are grouped for 10 minutes).
- Administrator user management, including role changes and deactivation. Deactivation revokes the user's active document grants.
- Access-request workflow: user requests a specific permission, owner receives a notification, approves or denies, and approval requires a short-lived owner-email OTP. Approved access lasts one hour.
- Session history records device/browser label, user-agent, IP address, last activity and revocation; revoked session tokens are rejected on the next API request. Concurrent sessions create admin audit/email alerts.
- Inline preview for read permission; downloads require explicit download permission or edit permission.
- Automated tests for authorization, registration, approvals, version history, expiry validation, file integrity, 2FA, sessions, read-only preview, and OTP-gated access requests.

## Requirements

- Python 3.11+
- Node.js 20+
- Windows, macOS, or Linux

## 1. Backend setup (Windows PowerShell)

Open PowerShell in the project folder:

```powershell
cd backend
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
# Open backend/.env and replace JWT_SECRET with a unique random value before deployment.
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

If PowerShell blocks virtual-environment activation, you can run `.venv\Scripts\python.exe` directly or use Command Prompt activation (`.venv\Scripts\activate.bat`).

### Create your own administrator

Stop any running backend first. From the `backend` directory, run:

```powershell
python create_admin.py
```

Enter your own email, name, and a strong password when prompted. The password is not echoed while you type. This creates the first administrator without embedding default credentials in the code. New users register in the browser and receive Viewer access; the administrator can promote them to Owner or Admin.

If you used the earlier starter and its three demo accounts already exist in your local database, disable those legacy accounts after creating your new administrator:

```powershell
python disable_demo_accounts.py
```

This deactivates the old sample accounts and revokes their active grants while preserving document/audit history. Do not run this script if you intentionally want to keep those sample accounts.

Start the API:

```powershell
uvicorn app.main:app --reload
```

API docs: http://127.0.0.1:8000/docs
Health check: http://127.0.0.1:8000/health

For local development, the API keeps a compatibility migration path for older SQLite databases. Back up `backend/trustvault.db` and `backend/storage` before updating an existing installation. For production, apply the schema using Alembic before starting FastAPI:

```powershell
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port $env:PORT
```

Set the Render start command to `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT` (with the Render service root set to `backend`). The initial migration is a schema bootstrap; future schema changes should be added as new explicit Alembic revisions.

## 2. Frontend setup (second terminal)

```powershell
cd frontend
npm install
copy .env.example .env
npm run dev
```

Open the URL Vite prints, usually http://localhost:5173. The login form is blank: create an account using **Create an account**. Self-registered users start as Viewers and cannot upload until an administrator promotes them to Owner.

## 3. Configure email notifications and 2FA (optional)

Configure the Resend email provider in `backend/.env`:

```env
RESEND_API_KEY=re_your_provider_key
RESEND_FROM_EMAIL=your-verified-sender@example.com
LOGIN_OTP_EVERY_TIME=false
```

Create a Resend account, verify the sender/domain required by your provider, and keep the API key private. The application sends mail through the Resend HTTPS API; SMTP variables are not used by the current notification service. Without `RESEND_API_KEY`, optional email notifications and email OTP cannot be delivered. Login works normally by default; set `LOGIN_OTP_EVERY_TIME=true` only when email delivery is configured and every sign-in should require an email OTP.

## 4. Google sign-in (optional)

See [`GOOGLE_SIGN_IN.md`](GOOGLE_SIGN_IN.md) for Google Cloud Console setup. Configure the same Web OAuth client ID as `GOOGLE_CLIENT_ID` on the backend and `VITE_GOOGLE_CLIENT_ID` on the frontend. Google ID tokens are verified on the server, verified Google email accounts receive only the Viewer role by default, and the browser never decides the user's role.

For Render, set `ENVIRONMENT=production`, a unique `JWT_SECRET` of at least 32 characters, `DATABASE_URL` to your managed PostgreSQL URL, `FRONTEND_ORIGIN` to the exact Vercel origin, and `GOOGLE_CLIENT_ID` if Google sign-in is enabled. In Vercel, set `VITE_API_URL` to your Render API base URL and `VITE_GOOGLE_CLIENT_ID` to the same Google Web client ID, then redeploy both services after changing environment variables. Never put a Google client secret in Vercel.

**Render storage warning:** the local filesystem storage used by this starter is not automatically durable across all Render service types/redeploys. Before storing important documents, configure a supported persistent disk or private object storage and verify backups. The project does not silently claim cloud object storage has been configured.

## 5. Run tests

From the `backend` directory with its virtual environment active:

```powershell
pytest -q
```

The included test suite exercises the security-sensitive API paths. Run it again after every change. The frontend bundle should also be checked with `npm run build` after `npm install`.

## 6. Suggested demo workflow

1. Create your administrator with `python create_admin.py`.
2. Register a second account through the browser.
3. In Admin → Users, promote that account to Owner.
4. Sign in as Owner, upload a harmless sample document, and optionally require approval.
5. Sign in as Admin and approve the request.
6. Share the document with a registered Viewer, optionally setting an expiry date.
7. Download the document and show the personalized watermark.
8. Upload a new version, inspect version history, and restore a prior version.
9. Check SHA-256 integrity, then use a local test to tamper with a stored file and verify downloads are blocked.
10. Revoke access or deactivate the Viewer, then verify their next API request is denied.
11. Review analytics and audit events, and verify the audit hash chain.
12. Configure Resend and enable email-based 2FA from Security Settings; optionally demonstrate Google sign-in after configuring a Google Web OAuth client ID.

## Security limitations

This remains an educational starter, not a production security certification. Email OTP depends on Resend delivery and proves control of the mailbox at challenge time, not a legal identity. Browser/user-agent/IP matching is a heuristic and can be spoofed; concurrent sessions can be legitimate. A watermark cannot prevent screenshots or remove copies already downloaded. The local SQLite database and hash-chained audit log can be rewritten by an attacker with full server/database access; the hash chain is tamper-evident, not independently immutable. Production use requires HTTPS, rate limiting, verified email, robust password recovery, CSRF protections where applicable, malware scanning, backups, independent append-only audit checkpoints, secret management, monitoring, and a professional security review.

## Environment and private data

See `backend/.env.example`. Never commit `.env`, database files, uploaded documents, access tokens, OTP codes, or email-provider secrets. Storage is private by default and is not mounted as a public static directory.
