
import json
import logging
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send an email through the Resend HTTPS API."""

    api_key = settings.resend_api_key
    from_email = settings.resend_from_email

    if not api_key or not from_email:
        logger.error("Resend is not configured: API key or sender is missing.")
        return False

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "text": body,
    }

    request = Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "TrustVault/1.0",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=20) as response:
            if 200 <= response.status < 300:
                logger.info("Resend email sent successfully.")
                return True

            logger.error("Resend returned HTTP status %s.", response.status)
            return False

    except HTTPError as exc:
        # Log the API's response to help diagnose delivery failures.
        # Never log the API key.
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""

        logger.error(
            "Resend request failed with HTTP status %s. Response: %s",
            exc.code,
            detail[:1000],
        )
        return False

    except (URLError, OSError, TimeoutError) as exc:
        logger.error(
            "Resend connection failed. Error type: %s",
            type(exc).__name__,
        )
        return False


def notify(
    db,
    actor_id,
    to_email: str,
    subject: str,
    body: str,
    resource_type="notification",
    resource_id=None,
):
    """Send a notification and record its outcome in the audit trail."""

    from app.services.audit import record_event

    sent = send_email(to_email, subject, body)

    record_event(
        db,
        actor_id,
        "email_notification",
        resource_type,
        resource_id,
        "success" if sent else "skipped_or_failed",
        {
            "recipient": to_email,
            "subject": subject[:120],
        },
    )

    return sent
