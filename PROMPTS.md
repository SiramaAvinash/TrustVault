# AI Assistance Log

> Replace these examples with your **actual dated prompts, outputs, bugs, corrections, tests, and real commit hashes** as you work. Do not submit fabricated dates or commits. The challenge asks for genuine records.

## Entry template
- Date/time:
- Prompt:
- Relevant AI output:
- Error or security concern found:
- Correction made:
- Test run and result:
- Commit hash/link:

## Suggested real entries to record
### Security review: cross-user document access
- Prompt: "Review the document detail, download, and list endpoints for IDOR/BOLA. Show a concrete attack request and propose a regression test."
- Record the actual finding, code change, test output, and commit after running it.

### Security review: revocation
- Prompt: "Check whether revoking a document grant blocks the viewer's very next download request, including when they know the document ID."
- Record the actual finding, code change, test output, and commit after running it.

### Audit integrity review
- Prompt: "Review this hash-chain design. Explain what it detects and what an attacker with database write access can still do."
- Record the actual limitation and any external checkpoint design you implement.

### Upload validation review
- Prompt: "Review file upload validation for size limits, extension spoofing, path traversal, and dangerous content."
- Record the actual test cases, results, and corrections.


## 2026-10-25 — Diagnose login test failures and Google sign-in integration
- Prompt/task: Inspect the submitted TrustVault project, run its existing tests, diagnose failures, and add a Google sign-in option without trusting client-supplied identity claims.
- AI output: Identified that `LOGIN_OTP_EVERY_TIME` defaulted to `true`, making password login return HTTP 503 when the email provider was not configured; proposed server-side Google ID-token verification and viewer-only account creation.
- Defect/omission discovered: The existing notification service uses Resend's HTTPS API, while several checks and README instructions referenced SMTP. The Google sign-in UI could not be tested against a live Google client because no client ID was supplied.
- Correction made: Defaulted email OTP to opt-in, aligned provider checks and environment documentation with Resend, added a Google ID-token verification module, linked verified Google identities by subject/email, added a database field and startup compatibility migration, added an Alembic migration scaffold for production, corrected authorization documentation, and made logout revoke the server-side session.
- Test run and result: Before correction, `python -m pytest -q` reported 21 failures and 2 passes, all caused by the unconfigured email OTP challenge blocking login. After correction, the original suite passed (23 passed). After adding logout and Google account-flow tests using mocked verified claims, `python -m pytest -q` passed (29 passed). Python `compileall` and Babel parser checks for the changed frontend files passed. Live Google verification, Alembic execution, and frontend production build could not be completed in this sandbox: network access was unavailable for installing `google-auth`, and the supplied `node_modules` contained Windows-specific native optional dependencies rather than the Linux Rollup binary.
- Commit hash/link: Not committed in this workspace; no commit hash is claimed.
