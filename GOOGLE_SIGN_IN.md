# Google sign-in setup

Google sign-in is implemented with Google Identity Services in the React frontend and server-side ID-token verification in FastAPI. It remains disabled until you configure your own Google Web OAuth client ID.

## 1. Create a Google OAuth Web client

1. Open the Google Cloud Console and select or create a project.
2. Configure the OAuth consent screen and provide the required app name, support email, and contact details.
3. Create an OAuth client ID with application type **Web application**.
4. Add authorized JavaScript origins for each exact frontend origin you use, for example:
   - `http://localhost:5173`
   - `https://YOUR-PROJECT.vercel.app`
5. Copy the **Client ID**. The GIS popup/callback flow in this project does not require a redirect URI.

Do not publish or commit any OAuth client secret. This implementation uses the public client ID only.

## 2. Configure the backend

In local `backend/.env`, set:

```env
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

In Render, add the same `GOOGLE_CLIENT_ID` environment variable to the backend service. Install dependencies from `backend/requirements.txt` so the maintained `google-auth` verifier is installed.

## 3. Configure the frontend

In local `frontend/.env`, set:

```env
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
VITE_API_URL=http://127.0.0.1:8000
```

In Vercel Project Settings → Environment Variables, add `VITE_GOOGLE_CLIENT_ID` with the same client ID and make sure `VITE_API_URL` points to the deployed Render API. Redeploy Vercel after updating variables.

## 4. Verify it

1. Open the frontend on an origin listed in Google Cloud Console.
2. Click **Continue with Google** and select a Google account.
3. Confirm that the API creates or links the account only after server-side token verification.
4. Confirm the new account receives the `viewer` role, not `owner` or `admin`.
5. Test an inactive TrustVault account and confirm Google sign-in is denied.
6. Test that a Google account cannot take over an account already linked to a different Google subject.
7. Check the backend audit trail for Google sign-in events.

The automated tests mock the verified Google claims to test account linking and role handling. They do not contact Google's live token verification service; finish a real sign-in smoke test after adding your own client ID. Google provider behavior, consent-screen publication, and domain restrictions depend on your Google Cloud configuration.
