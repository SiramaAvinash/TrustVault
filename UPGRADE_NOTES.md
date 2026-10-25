# Upgrade guide: original TrustVault → enhanced TrustVault

This guide is for the existing Windows project. Keep a backup before replacing any files.

## Step 1 — Stop the servers and back up your local data

Press `Ctrl+C` in both the backend and frontend terminals. Copy these if they exist:

- `backend/trustvault.db` — your local user/document database
- `backend/storage/` — uploaded private documents and version files
- `backend/.env` — local JWT/database/email-provider configuration
- `frontend/.env` — frontend API URL

Do not share `.env`, the database, or uploaded files publicly.

## Step 2 — Extract the enhanced project

Extract `TrustVault_Enhanced.zip` to a new folder, for example:

`C:\Users\siram\Desktop\TrustVault_Enhanced\TrustVault`

Copy your backed-up `backend/trustvault.db`, `backend/storage/`, and `.env` files into the matching locations in the enhanced project if you want to preserve existing local data. Keep the new `backend/.env.example` as a reference. Do not copy old source files over the new source files.

## Step 3 — Install the backend dependencies

In PowerShell:

```powershell
cd C:\Users\siram\Desktop\TrustVault_Enhanced\TrustVault\backend
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `.venv` already exists in the new folder, activate it rather than creating it again. The new requirements include `pypdf`, `reportlab`, and `Pillow` for watermarked downloads.

## Step 4 — Create an administrator with your own credentials

Make sure the backend server is stopped, then run:

```powershell
python create_admin.py
```

Enter your own email and strong password. No predefined login credentials are seeded by the enhanced project. If you copied a database from the previous version, this script also triggers the schema migration before creating/updating the administrator.

If the old sample accounts exist in the copied database, run this only after creating your own administrator:

```powershell
python disable_demo_accounts.py
```

This deactivates `admin@trustvault.local`, `owner@trustvault.local`, and `viewer@trustvault.local`, and revokes their active grants while preserving audit/document history. It does not delete uploaded documents. If you want to keep using an old sample account, skip this step.

## Step 5 — Start the backend

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/health` and confirm `{"status":"ok"}`. The API creates the new tables and adds missing columns when it starts. Always back up the database before an upgrade.

## Step 6 — Start the frontend

In a second PowerShell terminal:

```powershell
cd C:\Users\siram\Desktop\TrustVault_Enhanced\TrustVault\frontend
npm install
copy .env.example .env
npm run dev
```

If `frontend/.env` already exists, inspect it rather than overwriting it. It should contain `VITE_API_URL=http://127.0.0.1:8000`. Open the URL Vite prints, usually `http://localhost:5173`.

## Step 7 — Register and assign roles

1. Create a new account in the website with your own email and password. New accounts are Viewers.
2. Sign in as the administrator created in Step 4.
3. Open **Users** and promote the appropriate account to **Owner**.
4. Sign in as that Owner to upload documents and manage grants.

Public registration cannot set the role; only an administrator can promote accounts.

## Step 8 — Configure email (optional)

Edit `backend/.env` and set `RESEND_API_KEY` and `RESEND_FROM_EMAIL`. The notification implementation uses the Resend HTTPS API; SMTP variables in older versions are not used. Restart the backend. Until Resend delivery is configured, notifications are recorded as skipped/failed and email-based 2FA cannot be enabled.

## Step 9 — Run security tests

```powershell
cd ..\backend
.venv\Scripts\Activate.ps1
pytest -q
```

The included suite currently covers registration, authorization, grant expiry validation, approval gating, version restore, file integrity checks, and 2FA configuration. Also test the frontend manually after `npm install` using the demo workflow in `README.md`.


## TrustVault security workflow extension

This build adds `DeviceSession` and `AccessRequest` tables, granular `can_download` / `can_share` grant fields, owner OTP approval, inline preview, session revocation, concurrent-session alerts, and owner notification for denied document operations. Startup migrations add the new grant columns to existing SQLite databases. Back up `backend/trustvault.db` and `backend/storage` before upgrading.

Run backend tests after upgrade:
`python -m pytest -q`

The email challenge requires a working Resend configuration. Browser+IP matching is only a heuristic, not cryptographic device identity. OTP-approved grants expire after one hour. Read preview cannot stop screenshots or all browser save paths.


## Google sign-in and configuration corrections

This upgrade adds an optional Google Identity Services button and `/api/auth/google` endpoint. Follow `GOOGLE_SIGN_IN.md` and set `GOOGLE_CLIENT_ID` in Render plus `VITE_GOOGLE_CLIENT_ID` in Vercel. The ID is public configuration; do not add a Google client secret to frontend environment variables.

The email service in this codebase uses the Resend HTTPS API, not SMTP. Configure `RESEND_API_KEY` and `RESEND_FROM_EMAIL` if you want email notifications or email OTP. `LOGIN_OTP_EVERY_TIME` defaults to `false` so the app remains usable when optional email delivery is not configured.

The ZIP distributed with this upgrade intentionally excludes `.env` files, local databases, stored document bytes, `.git` history, Python bytecode, and `node_modules`. Back up your own database/storage and configure secrets independently. Before using Render for important documents, confirm durable private storage and backups; the local filesystem alone is not a durable object-storage solution.
