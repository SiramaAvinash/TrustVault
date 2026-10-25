# TrustVault upgrade verification report

Date: 2026-10-25

## Changes included

- Fixed the default login behavior so optional email OTP does not block all password logins when the email provider is not configured.
- Aligned email-delivery checks and setup documentation with the code's actual Resend HTTPS API integration.
- Added optional Google Identity Services sign-in UI and a FastAPI `/api/auth/google` endpoint.
- Added server-side Google ID-token verification through the maintained `google-auth` package, verified-email checks, least-privilege Viewer account creation, safe account linking, and subject/email collision rejection.
- Added the `google_sub` user field and a compatibility migration for existing local databases.
- Added an Alembic bootstrap and Google-identity migration scaffold; production is configured to expect migrations before application startup.
- Made logout revoke the server-side session so copied session tokens are rejected on the next request.
- Added password visibility control and Google sign-in setup documentation.
- Corrected API authorization documentation and added deployment/storage cautions.
- Removed local secrets, local databases, stored document bytes, Git history, Python bytecode, and installed frontend dependencies from the distributable archive.

## Verification performed

- Backend automated tests: **29 passed** (`python -m pytest -q`).
- Python compilation: passed for backend application, tests, and migration source (`python -m compileall -q app tests migrations`).
- Frontend source parsing: passed for `src/App.jsx`, `src/main.jsx`, and `src/api/client.js` using the Babel parser bundled in the supplied dependencies.
- Existing tests cover authentication, cross-user authorization, read-only permission enforcement, revocation, upload validation, audit chain verification, document versions, sessions, access requests, and the added Google-account flow handling.

## Not verified in this sandbox

- A full Vite production build could not run because the supplied `node_modules` came from Windows and did not contain Rollup's Linux native optional dependency. The final ZIP excludes `node_modules`; run `npm ci` and `npm run build` on your development machine or CI.
- Live Google token verification was not performed because no Google client ID was supplied and the sandbox could not download the `google-auth` dependency. The route behavior tests mock claims returned by a successful verifier; they do not replace a real Google sign-in smoke test.
- Alembic migrations were added but could not be executed here because Alembic was not installed and package downloads were unavailable. Run `pip install -r requirements.txt` then `alembic upgrade head` in a clean environment before deploying.
- Render/Vercel hosted behavior was not tested from this workspace. Set and verify the production environment variables and URLs as described in `README.md` and `GOOGLE_SIGN_IN.md`.
- This is not a security certification. Production use still needs durable private storage, tested backups, rate limiting, independent audit checkpoints, monitoring, and a professional security review.

## Important deployment notes

- Set `ENVIRONMENT=production` and a unique `JWT_SECRET` of at least 32 characters in Render. Placeholder values are rejected in production mode.
- Set `FRONTEND_ORIGIN` to the exact deployed Vercel origin.
- For Google sign-in, set `GOOGLE_CLIENT_ID` in Render and `VITE_GOOGLE_CLIENT_ID` in Vercel to the same Web OAuth client ID.
- The current document storage service uses a private local filesystem directory. Confirm a persistent disk or private object storage is configured before using it for important files; do not assume ephemeral hosting storage survives redeploys.
- If secrets were ever committed to Git or included in a shared archive, rotate them in the relevant provider dashboards. Excluding `.env` from this ZIP does not erase prior copies from your existing repository history.
