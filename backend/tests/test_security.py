def login(client, email, password):
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}

def upload(client, headers, filename="hello.txt", content=b"hello TrustVault"):
    return client.post("/api/documents", headers=headers,
        data={"title": "Confidential Demo", "category": "Contracts"},
        files={"file": (filename, content, "text/plain")})

def test_cross_user_cannot_read_or_download(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    other = login(client, "other@example.com", "OtherPass123!")
    created = upload(client, owner)
    assert created.status_code == 200, created.text
    doc_id = created.json()["id"]
    assert client.get(f"/api/documents/{doc_id}", headers=other).status_code == 403
    assert client.get(f"/api/documents/{doc_id}/download", headers=other).status_code == 403

def test_grant_and_immediate_revocation(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    created = upload(client, owner)
    doc_id = created.json()["id"]
    assert client.post(f"/api/documents/{doc_id}/grants", headers=owner,
        json={"email": "viewer@example.com", "permission": "download"}).status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 200
    assert client.delete(f"/api/documents/{doc_id}/grants/3", headers=owner).status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 403

def test_read_grant_cannot_edit(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    doc_id = upload(client, owner).json()["id"]
    client.post(f"/api/documents/{doc_id}/grants", headers=owner,
                json={"email": "viewer@example.com", "permission": "read"})
    response = client.patch(f"/api/documents/{doc_id}", headers=viewer, json={"title": "Stolen"})
    assert response.status_code == 403

def test_invalid_extension_rejected(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    response = upload(client, owner, "malware.exe", b"not executable")
    assert response.status_code == 400

def test_pdf_signature_validation(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    response = upload(client, owner, "fake.pdf", b"not a real pdf")
    assert response.status_code == 400

def test_audit_chain_verifies(client):
    admin = login(client, "admin@example.com", "AdminPass123!")
    owner = login(client, "owner@example.com", "OwnerPass123!")
    upload(client, owner)
    result = client.get("/api/audit/verify", headers=admin)
    assert result.status_code == 200
    assert result.json()["valid"] is True, result.text

def test_non_admin_cannot_read_global_audit(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    assert client.get("/api/audit", headers=owner).status_code == 403

def test_registration_uses_viewer_role_and_can_login(client):
    response = client.post("/api/auth/register", json={
        "email": "new.user@example.com", "full_name": "New User", "password": "StrongPassword123"
    })
    assert response.status_code == 201, response.text
    assert response.json()["role"] == "viewer"
    token = login(client, "new.user@example.com", "StrongPassword123")
    assert client.get("/api/auth/me", headers=token).status_code == 200

def test_registration_rejects_weak_password_and_duplicate_email(client):
    weak = client.post("/api/auth/register", json={"email":"new.user@example.com", "full_name":"New User", "password":"short"})
    assert weak.status_code == 422
    payload = {"email":"new.user@example.com", "full_name":"New User", "password":"StrongPassword123"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409

def test_approval_blocks_sharing_until_admin_approves(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    admin = login(client, "admin@example.com", "AdminPass123!")
    created = client.post("/api/documents", headers=owner,
        data={"title":"Needs Approval", "category":"Legal", "requires_approval":"true"},
        files={"file":("legal.txt", b"private legal text", "text/plain")})
    assert created.status_code == 200, created.text
    doc_id = created.json()["id"]
    denied = client.post(f"/api/documents/{doc_id}/grants", headers=owner,
                         json={"email":"viewer@example.com", "permission":"read"})
    assert denied.status_code == 409
    pending = client.get("/api/approvals", headers=admin)
    assert pending.status_code == 200 and pending.json()
    approval_id = pending.json()[0]["id"]
    assert client.patch(f"/api/approvals/{approval_id}", headers=admin, json={"status":"approved"}).status_code == 200
    granted = client.post(f"/api/documents/{doc_id}/grants", headers=owner,
                          json={"email":"viewer@example.com", "permission":"read"})
    assert granted.status_code == 200, granted.text

def test_version_history_and_restore(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    created = upload(client, owner, "report.txt", b"version one")
    doc_id = created.json()["id"]
    changed = client.post(f"/api/documents/{doc_id}/versions", headers=owner,
        data={"note":"updated report"}, files={"file":("report-v2.txt", b"version two", "text/plain")})
    assert changed.status_code == 200, changed.text
    versions = client.get(f"/api/documents/{doc_id}/versions", headers=owner)
    assert versions.status_code == 200 and len(versions.json()) == 1
    restored = client.post(f"/api/documents/{doc_id}/versions/{versions.json()[0]['id']}/restore", headers=owner)
    assert restored.status_code == 200, restored.text
    download = client.get(f"/api/documents/{doc_id}/download?watermark=false", headers=owner)
    assert download.status_code == 200 and b"version one" in download.content

def test_integrity_check_blocks_tampered_file(client):
    from app.core.config import storage_path
    from app.db.session import SessionLocal
    from app.models.entities import Document
    owner = login(client, "owner@example.com", "OwnerPass123!")
    created = upload(client, owner, "report.txt", b"original")
    doc_id = created.json()["id"]
    db = SessionLocal()
    try:
        doc = db.get(Document, doc_id); file_path = storage_path / doc.storage_filename
        file_path.write_bytes(b"tampered")
    finally:
        db.close()
    check = client.get(f"/api/documents/{doc_id}/integrity", headers=owner)
    assert check.status_code == 200 and check.json()["valid"] is False
    assert client.get(f"/api/documents/{doc_id}/download", headers=owner).status_code == 500

def test_grant_expiry_is_validated(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    past = ("2000-01-01T00:00:00+00:00")
    doc_id = upload(client, owner).json()["id"]
    response = client.post(f"/api/documents/{doc_id}/grants", headers=owner,
        json={"email":"viewer@example.com", "permission":"read", "expires_at":past})
    assert response.status_code == 400

def test_2fa_cannot_be_enabled_without_email_provider(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    response = client.patch("/api/auth/2fa", headers=owner, json={"enabled":True,"password":"OwnerPass123!"})
    assert response.status_code == 503

def test_expired_grant_is_denied_on_next_request(client):
    from datetime import datetime, timedelta, timezone
    from app.db.session import SessionLocal
    from app.models.entities import Grant
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    doc_id = upload(client, owner).json()["id"]
    response = client.post(f"/api/documents/{doc_id}/grants", headers=owner,
        json={"email":"viewer@example.com", "permission":"read", "expires_at":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()})
    assert response.status_code == 200, response.text
    db = SessionLocal()
    try:
        grant = db.query(Grant).filter(Grant.document_id == doc_id, Grant.user_id == 3).first()
        grant.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1); db.commit()
    finally: db.close()
    assert client.get(f"/api/documents/{doc_id}", headers=viewer).status_code == 403

def test_viewer_cannot_upload(client):
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    response = upload(client, viewer)
    assert response.status_code == 403


def test_read_permission_does_not_allow_download(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    doc_id = upload(client, owner).json()["id"]
    assert client.post(f"/api/documents/{doc_id}/grants", headers=owner,
        json={"email":"viewer@example.com", "permission":"read"}).status_code == 200
    assert client.get(f"/api/documents/{doc_id}", headers=viewer).status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 403

def test_session_can_be_revoked_and_token_rejected(client):
    response = client.post("/api/auth/login", json={"email":"viewer@example.com","password":"ViewerPass123!"})
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    session_id = response.json()["session_id"]
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.delete(f"/api/sessions/{session_id}", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401

def test_access_request_requires_owner_otp_before_temporary_grant_with_resend(client, monkeypatch):
    from app.api import routes
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    monkeypatch.setattr(routes.settings, "resend_api_key", "re_test")
    monkeypatch.setattr(routes.settings, "resend_from_email", "test@trustvault.local")
    monkeypatch.setattr(routes, "send_email", lambda *args, **kwargs: True)
    doc_id = upload(client, owner).json()["id"]
    request_response = client.post(f"/api/documents/{doc_id}/access-requests", headers=viewer,
        json={"permission":"download", "reason":"Need to review offline"})
    assert request_response.status_code == 200, request_response.text
    request_id = request_response.json()["id"]
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 403
    assert client.post(f"/api/access-requests/{request_id}/approve", headers=owner).status_code == 200
    from app.db.session import SessionLocal
    from app.models.entities import AccessRequest
    db = SessionLocal()
    try:
        row = db.get(AccessRequest, request_id)
        code = "123456"
        row.otp_hash = __import__("hashlib").sha256(code.encode()).hexdigest()
        db.commit()
    finally:
        db.close()
    verified = client.post(f"/api/access-requests/{request_id}/verify", headers=owner, json={"code":code})
    assert verified.status_code == 200, verified.text
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 200


def test_read_grant_allows_preview_but_not_download(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    doc_id = upload(client, owner, "readme.txt", b"preview only").json()["id"]
    assert client.post(f"/api/documents/{doc_id}/grants", headers=owner,
        json={"email":"viewer@example.com", "permission":"read"}).status_code == 200
    preview = client.get(f"/api/documents/{doc_id}/preview", headers=viewer)
    assert preview.status_code == 200 and preview.content == b"preview only"
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 403

def test_new_device_requires_email_otp_when_resend_is_configured(client, monkeypatch):
    from app.api import routes
    monkeypatch.setattr(routes.settings, "resend_api_key", "re_test")
    monkeypatch.setattr(routes.settings, "resend_from_email", "test@trustvault.local")
    sent = {}
    def fake_send(to, subject, body):
        sent["to"] = to
        sent["code"] = __import__("re").search(r"code is (\d{6})", body).group(1)
        return True
    monkeypatch.setattr(routes, "send_email", fake_send)
    response = client.post("/api/auth/login", json={"email":"viewer@example.com","password":"ViewerPass123!"})
    assert response.status_code == 200 and response.json()["requires_2fa"] is True
    verified = client.post("/api/auth/2fa/verify", json={"email":"viewer@example.com","code":sent["code"]})
    assert verified.status_code == 200, verified.text
    assert verified.json().get("session_id")


def test_admin_role_does_not_automatically_read_private_document(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    admin = login(client, "admin@example.com", "AdminPass123!")
    doc_id = upload(client, owner).json()["id"]
    assert client.get(f"/api/documents/{doc_id}", headers=admin).status_code == 403
    assert client.get(f"/api/documents/{doc_id}/download", headers=admin).status_code == 403

def test_denied_download_is_audited(client):
    owner = login(client, "owner@example.com", "OwnerPass123!")
    viewer = login(client, "viewer@example.com", "ViewerPass123!")
    doc_id = upload(client, owner).json()["id"]
    assert client.get(f"/api/documents/{doc_id}/download", headers=viewer).status_code == 403
    owner_events = client.get(f"/api/documents/{doc_id}/audit", headers=owner)
    assert owner_events.status_code == 200
    assert any(event["action"] == "document_download_denied" for event in owner_events.json())


def test_logout_revokes_the_server_session(client):
    headers = login(client, "owner@example.com", "OwnerPass123!")
    signed_out = client.post("/api/auth/logout", headers=headers)
    assert signed_out.status_code == 200, signed_out.text
    rejected = client.get("/api/auth/me", headers=headers)
    assert rejected.status_code == 401


def test_google_login_creates_least_privilege_viewer(client, monkeypatch):
    from app.api import routes
    from app.core.config import settings
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    monkeypatch.setattr(routes, "verify_google_credential", lambda credential, client_id: {
        "sub": "google-subject-123", "email": "google.user@example.com",
        "email_verified": True, "name": "Google User",
        "iss": "https://accounts.google.com",
    })
    response = client.post("/api/auth/google", json={"credential": "test-credential-" + "x" * 40})
    assert response.status_code == 200, response.text
    assert response.json()["user"]["role"] == "viewer"
    token = {"Authorization": "Bearer " + response.json()["access_token"]}
    me = client.get("/api/auth/me", headers=token)
    assert me.status_code == 200
    assert me.json()["email"] == "google.user@example.com"


def test_google_login_links_only_to_matching_verified_email_identity(client, monkeypatch):
    from app.api import routes
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.models.entities import User
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    monkeypatch.setattr(routes, "verify_google_credential", lambda credential, client_id: {
        "sub": "existing-google-subject", "email": "owner@example.com",
        "email_verified": True, "name": "Owner One",
        "iss": "https://accounts.google.com",
    })
    response = client.post("/api/auth/google", json={"credential": "test-credential-" + "x" * 40})
    assert response.status_code == 200, response.text
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "owner@example.com").one()
        assert user.google_sub == "existing-google-subject"
        assert user.role == "owner"
    finally:
        db.close()


def test_google_login_rejects_inactive_account(client, monkeypatch):
    from app.api import routes
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.models.entities import User
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "viewer@example.com").one()
        user.is_active = False
        db.commit()
    finally:
        db.close()
    monkeypatch.setattr(routes, "verify_google_credential", lambda credential, client_id: {
        "sub": "inactive-google-subject", "email": "viewer@example.com",
        "email_verified": True, "name": "Viewer One",
        "iss": "https://accounts.google.com",
    })
    response = client.post("/api/auth/google", json={"credential": "test-credential-" + "x" * 40})
    assert response.status_code == 403


def test_google_login_rejects_subject_email_collision(client, monkeypatch):
    from app.api import routes
    from app.core.config import settings
    from app.db.session import SessionLocal
    from app.models.entities import User
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    db = SessionLocal()
    try:
        owner = db.query(User).filter(User.email == "owner@example.com").one()
        owner.google_sub = "subject-linked-to-owner"
        db.commit()
    finally:
        db.close()
    monkeypatch.setattr(routes, "verify_google_credential", lambda credential, client_id: {
        "sub": "subject-linked-to-owner", "email": "viewer@example.com",
        "email_verified": True, "name": "Conflicting Identity",
        "iss": "https://accounts.google.com",
    })
    response = client.post("/api/auth/google", json={"credential": "test-credential-" + "x" * 40})
    assert response.status_code == 409


def test_google_login_reports_missing_server_configuration(client, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "google_client_id", "")
    response = client.post("/api/auth/google", json={"credential": "test-credential-" + "x" * 40})
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"].lower()
