import io
from app.models import db, Document, DocumentShare, AuditLog, ActionTypeEnum

def test_positive_upload_share_download_flow(app, owner_client, viewer_client, viewer_user):
    """
    Positive test: Owner uploads a document, shares with Viewer,
    and Viewer downloads the document successfully.
    """
    # 1. Owner uploads document
    file_content = b"Confidential Executive Summary 2026."
    data = {
        'title': 'Executive Summary',
        'document': (io.BytesIO(file_content), 'summary.pdf')
    }
    upload_res = owner_client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert upload_res.status_code == 200

    # Retrieve uploaded doc
    doc = Document.query.filter_by(title='Executive Summary').first()
    assert doc is not None
    assert doc.original_filename == 'summary.pdf'

    # 2. Owner shares document with Viewer (Bob)
    share_res = owner_client.post(f'/share/{doc.id}', data={'user_id': viewer_user.id}, follow_redirects=True)
    assert share_res.status_code == 200

    # Verify active share exists in DB
    share = DocumentShare.query.filter_by(document_id=doc.id, user_id=viewer_user.id).first()
    assert share is not None
    assert share.is_active is True

    # 3. Viewer downloads document successfully
    download_res = viewer_client.get(f'/download/{doc.id}')
    assert download_res.status_code == 200
    assert download_res.data == file_content
    assert download_res.headers.get('Content-Disposition') is not None
    assert 'summary.pdf' in download_res.headers.get('Content-Disposition')

def test_idor_viewer_cannot_delete_document(app, sample_document, viewer_client):
    """
    Negative test (IDOR check): Viewer attempts to hit /delete/<doc_id> directly
    via POST or GET -> Expect HTTP 403 Forbidden. Never rely on frontend button hiding.
    """
    # Attempt via POST
    delete_post_res = viewer_client.post(f'/delete/{sample_document.id}')
    assert delete_post_res.status_code == 403

    # Attempt via GET
    delete_get_res = viewer_client.get(f'/delete/{sample_document.id}')
    assert delete_get_res.status_code == 403

    # Verify document still exists in database (not deleted)
    doc_in_db = db.session.get(Document, sample_document.id)
    assert doc_in_db is not None

def test_idor_other_owner_cannot_delete_foreign_document(app, sample_document, other_owner_client):
    """
    Negative test (IDOR check): Another authenticated Owner attempts to delete
    a document owned by a different Owner -> Expect HTTP 403 Forbidden.
    """
    res = other_owner_client.post(f'/delete/{sample_document.id}')
    assert res.status_code == 403

    doc_in_db = db.session.get(Document, sample_document.id)
    assert doc_in_db is not None

def test_idor_unshared_document_download_forbidden(app, sample_document, viewer_client):
    """
    Negative test (IDOR check): Viewer attempts to download a document that has NOT
    been shared with them -> Expect HTTP 403 Forbidden.
    """
    res = viewer_client.get(f'/download/{sample_document.id}')
    assert res.status_code == 403

def test_idor_viewer_cannot_share_document(app, sample_document, viewer_client, other_owner_user):
    """
    Negative test (IDOR check): Viewer attempts to share an owner's document
    with another user -> Expect HTTP 403 Forbidden.
    """
    res = viewer_client.post(f'/share/{sample_document.id}', data={'user_id': other_owner_user.id})
    assert res.status_code == 403

def test_instantaneous_revocation(app, sample_document, owner_client, viewer_client, viewer_user):
    """
    Instantaneous Revocation test:
    1. Owner shares document with Viewer.
    2. Viewer downloads successfully (HTTP 200).
    3. Owner revokes access.
    4. Viewer immediately attempts to download -> Rejected with HTTP 403 Forbidden.
    """
    # 1. Share document
    owner_client.post(f'/share/{sample_document.id}', data={'user_id': viewer_user.id})

    # 2. Viewer downloads successfully
    first_download = viewer_client.get(f'/download/{sample_document.id}')
    assert first_download.status_code == 200

    # 3. Owner revokes access
    revoke_res = owner_client.post(f'/revoke/{sample_document.id}/{viewer_user.id}', follow_redirects=True)
    assert revoke_res.status_code == 200

    # Verify DB reflects inactive status
    share = DocumentShare.query.filter_by(document_id=sample_document.id, user_id=viewer_user.id).first()
    assert share.is_active is False
    assert share.revoked_at is not None

    # 4. Instantaneous termination: next request immediately returns 403 Forbidden
    second_download = viewer_client.get(f'/download/{sample_document.id}')
    assert second_download.status_code == 403

def test_admin_audit_stream_restricted_to_admin(admin_client, owner_client, viewer_client):
    """
    Verifies that the audit stream is strictly accessible by Admin (read-only).
    Viewers and Owners must receive HTTP 403 Forbidden.
    """
    # Admin gets 200 OK
    admin_res = admin_client.get('/admin/audit-logs')
    assert admin_res.status_code == 200
    assert b"Tamper-Resistant Audit Trail" in admin_res.data

    # Owner gets 403 Forbidden
    owner_res = owner_client.get('/admin/audit-logs')
    assert owner_res.status_code == 403

    # Viewer gets 403 Forbidden
    viewer_res = viewer_client.get('/admin/audit-logs')
    assert viewer_res.status_code == 403

def test_access_denied_creates_audit_log_entry(app, sample_document, viewer_client, viewer_user):
    """
    Verifies that any unauthorized request (IDOR or role violation) triggers an
    ACCESS_DENIED audit log entry in the immutable ledger.
    """
    initial_denied_count = AuditLog.query.filter_by(action_type=ActionTypeEnum.ACCESS_DENIED.value).count()

    # Attempt forbidden download
    res = viewer_client.get(f'/download/{sample_document.id}')
    assert res.status_code == 403

    new_denied_count = AuditLog.query.filter_by(action_type=ActionTypeEnum.ACCESS_DENIED.value).count()
    assert new_denied_count == initial_denied_count + 1

    latest_denied = AuditLog.query.filter_by(action_type=ActionTypeEnum.ACCESS_DENIED.value).order_by(AuditLog.id.desc()).first()
    assert latest_denied.user_id == viewer_user.id
    assert latest_denied.target_document_id == sample_document.id
    assert latest_denied.status_code == 403
