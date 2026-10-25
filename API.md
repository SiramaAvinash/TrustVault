# TrustVault API Authorization Reference

All endpoints are prefixed by `/api`. Protected endpoints require `Authorization: Bearer <token>`. The exact interactive schema is available at `/docs` while the backend is running.

| Endpoint | Authorization / purpose |
|---|---|
| `POST /auth/register` | Public; creates a Viewer account; password must be strong and email unique |
| `POST /auth/login` | Public; returns a token, or starts email OTP flow when user 2FA, optional every-login OTP, or configured new-device challenge applies |
| `POST /auth/google` | Public when Google is configured; verifies the Google ID token server-side; new accounts receive Viewer role |
| `POST /auth/logout` | Authenticated; revokes the current server-side session so the token is rejected on its next request |
| `POST /auth/2fa/verify` | Public OTP exchange; code expires and has a bounded attempt count |
| `PATCH /auth/2fa` | Authenticated user; requires current password and configured Resend email delivery to enable |
| `GET /auth/me` | Authenticated user |
| `GET /users` | Administrator only |
| `PATCH /users/{id}` | Administrator only; role changes, activation/deactivation; cannot self-demote/deactivate |
| `GET /analytics` | Authenticated; metrics scoped to user's accessible documents/events; global metrics for admin |
| `POST /documents` | Owner or admin only; validates extension/signature/size and stores privately; optional approval requirement |
| `GET /documents` | Authenticated; only owned/granted documents, unless admin; supports title/category/owner/date/file-type/permission/hash/sort filters |
| `GET /documents/{id}` | Owner or current non-expired grant with metadata/read capability; administrator role alone does not bypass document access |
| `GET /documents/{id}/download` | Owner or explicit download/edit grant; verifies stored SHA-256 and applies personalized watermark by default |
| `GET /documents/{id}/integrity` | Same read authorization; recomputes stored-file SHA-256 |
| `PATCH /documents/{id}` | Owner or current edit grantee; metadata fields only |
| `DELETE /documents/{id}` | Document owner only; delete is audited and private version files are removed |
| `GET /documents/{id}/versions` | Current read-authorized user |
| `POST /documents/{id}/versions` | Owner/admin/current edit grantee; snapshots current file before replacement |
| `POST /documents/{id}/versions/{version_id}/restore` | Owner/admin/current edit grantee |
| `GET /documents/{id}/grants` | Owner or current recipient with share permission; shows active non-expired grants |
| `POST /documents/{id}/grants` | Owner or current recipient with share permission; read/edit/download/share and optional future expiry; approval required if enabled |
| `DELETE /documents/{id}/grants/{user_id}` | Owner or administrator; immediate server-side revocation |
| `POST /documents/{id}/approval-request` | Owner or admin; places sharing on hold until approval |
| `GET /approvals` | Administrator only |
| `PATCH /approvals/{id}` | Administrator only; approve/reject pending requests |
| `GET /audit` | Administrator only; supports action/outcome/actor filters |
| `GET /documents/{id}/audit` | Owner or administrator |
| `GET /audit/verify` | Administrator only; verifies the hash chain |

A user's role alone does not grant read access to every document. Current grants and expiry are checked server-side on each request. Deactivating a user revokes their active grants. Do not rely on hidden UI buttons as a security control.


## Additional security endpoints

- `GET /api/documents/{id}/preview` — inline preview with read permission and SHA-256 integrity check.
- `POST /api/documents/{id}/access-requests` — request `read`, `edit`, `download`, or `share` permission; body may include `reason`.
- `GET /api/access-requests` — own requests and requests for documents owned by the current user (Admin sees request metadata globally).
- `POST /api/access-requests/{id}/approve` — owner starts a five-minute OTP challenge via email.
- `POST /api/access-requests/{id}/verify` — owner verifies `{ "code": "123456" }`; successful approval grants the requested capability for one hour.
- `POST /api/access-requests/{id}/deny` — owner denies a pending request.
- `GET /api/sessions` — list the current user's session records.
- `DELETE /api/sessions/{session_id}` — revoke a session; its token is rejected on its next API request.
- New-device sign-in challenge is activated when Resend delivery is configured; account 2FA remains an explicit setting. Google sign-in also requires `GOOGLE_CLIENT_ID` and frontend `VITE_GOOGLE_CLIENT_ID`.

### Permission semantics
- `read`: document metadata and inline preview; direct download is denied.
- `edit`: read/preview, metadata edits and download.
- `download`: metadata and download, no edit.
- `share`: metadata and share-management API, no edit/download by default.
- Owner permissions are implicit for their own document. Admin role management does not automatically grant access to private document contents.
