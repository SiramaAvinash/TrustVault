"""Google OpenID Connect ID-token verification.

The frontend sends the ID token credential from Google Identity Services. The
backend verifies signature, issuer, audience, and expiry with Google's maintained
verification library; decoded, unverified JWT claims are never trusted.
"""
from fastapi import HTTPException


def verify_google_credential(credential: str, client_id: str) -> dict:
    if not client_id:
        raise HTTPException(status_code=503, detail="Google sign-in is not configured on this server")
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        claims = id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            audience=client_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        # Avoid returning provider details or the supplied credential to the client.
        raise HTTPException(status_code=401, detail="Google sign-in credential is invalid or expired") from exc

    if claims.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}:
        raise HTTPException(status_code=401, detail="Google sign-in issuer is invalid")
    if not claims.get("email_verified"):
        raise HTTPException(status_code=401, detail="Google account email must be verified")
    if not claims.get("sub") or not claims.get("email"):
        raise HTTPException(status_code=401, detail="Google sign-in did not return a verified identity")
    return claims
