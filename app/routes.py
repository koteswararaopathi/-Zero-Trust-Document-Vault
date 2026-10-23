import os
import uuid
import hashlib
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    send_from_directory, current_app, abort, jsonify, g
)
from werkzeug.utils import secure_filename
from app.models import db, Document, DocumentShare, User, RoleEnum, ActionTypeEnum
from app.rbac import get_current_user, require_role, require_document_access
from app.audit import record_audit_log

routes_bp = Blueprint('routes', __name__)

@routes_bp.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('auth.login'))
    return redirect(url_for('routes.dashboard'))

@routes_bp.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('auth.login'))

    owned_documents = []
    shared_documents = []
    viewers_list = []

    if user.is_owner or user.is_admin:
        owned_documents = Document.query.filter_by(owner_id=user.id).order_by(Document.created_at.desc()).all()
        # Fetch potential viewers for the share dropdown
        viewers_list = User.query.filter(User.id != user.id, User.role == RoleEnum.VIEWER.value).all()

    if user.is_viewer or user.is_admin:
        # Fetch documents actively shared with this viewer
        shares = DocumentShare.query.filter_by(user_id=user.id, is_active=True).all()
        shared_documents = [share.document for share in shares if share.document]

    return render_template(
        'dashboard.html',
        user=user,
        owned_documents=owned_documents,
        shared_documents=shared_documents,
        viewers_list=viewers_list
    )

@routes_bp.route('/upload', methods=['POST'])
@require_role(RoleEnum.OWNER, RoleEnum.ADMIN)
def upload_document():
    current_user = get_current_user()
    if 'document' not in request.files:
        flash("No file part provided in request.", "danger")
        return redirect(url_for('routes.dashboard'))

    file = request.files['document']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('routes.dashboard'))

    title = request.form.get('title', '').strip() or file.filename
    raw_filename = secure_filename(file.filename) or "unnamed_document"
    ext = os.path.splitext(raw_filename)[1]
    unique_stored_name = f"{uuid.uuid4().hex}{ext}"

    os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_stored_name)

    # Read content, compute SHA-256 file checksum, and save safely
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    with open(file_path, 'wb') as f:
        f.write(file_bytes)

    document = Document(
        title=title,
        original_filename=raw_filename,
        stored_filename=unique_stored_name,
        file_size=file_size,
        file_hash=file_hash,
        mime_type=file.content_type or 'application/octet-stream',
        owner_id=current_user.id
    )
    db.session.add(document)
    db.session.commit()

    # Tamper-resistant audit trail entry
    record_audit_log(
        action_type=ActionTypeEnum.WRITE,
        user_id=current_user.id,
        target_document_id=document.id,
        status_code=201
    )

    flash(f"Document '{title}' uploaded securely (SHA-256: {file_hash[:12]}...).", "success")
    return redirect(url_for('routes.dashboard'))

@routes_bp.route('/download/<int:doc_id>')
@require_document_access(permission_type='read')
def download_document(doc_id: int):
    """
    Downloads document file.
    Protected by @require_document_access('read'):
    - Verifies ownership or active share in real-time.
    - If unauthorized, returns HTTP 403 Forbidden.
    """
    current_user = get_current_user()
    document = g.current_document

    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, document.stored_filename)

    if not os.path.exists(file_path):
        flash("File missing from secure storage vault.", "danger")
        abort(404, description="Stored file not found on server")

    # Record successful READ in audit chain
    record_audit_log(
        action_type=ActionTypeEnum.READ,
        user_id=current_user.id,
        target_document_id=document.id,
        status_code=200
    )

    return send_from_directory(
        upload_folder,
        document.stored_filename,
        as_attachment=True,
        download_name=document.original_filename
    )

@routes_bp.route('/share/<int:doc_id>', methods=['POST'])
@require_document_access(permission_type='share')
def share_document(doc_id: int):
    """
    Grants read access on document to a designated Viewer.
    Strictly restricted to the Document Owner.
    """
    current_user = get_current_user()
    document = g.current_document

    target_user_id = request.form.get('user_id', type=int)
    target_username = request.form.get('username', '').strip()

    target_user = None
    if target_user_id:
        target_user = db.session.get(User, target_user_id)
    elif target_username:
        target_user = User.query.filter_by(username=target_username).first()

    if not target_user:
        flash("Specified user was not found.", "danger")
        return redirect(url_for('routes.dashboard'))

    if target_user.id == current_user.id:
        flash("You are already the owner of this document.", "warning")
        return redirect(url_for('routes.dashboard'))

    # Check for existing share
    existing_share = DocumentShare.query.filter_by(
        document_id=document.id,
        user_id=target_user.id
    ).first()

    if existing_share:
        existing_share.is_active = True
        existing_share.revoked_at = None
        existing_share.granted_by_id = current_user.id
    else:
        new_share = DocumentShare(
            document_id=document.id,
            user_id=target_user.id,
            granted_by_id=current_user.id,
            is_active=True
        )
        db.session.add(new_share)

    db.session.commit()

    # Audit log
    record_audit_log(
        action_type=ActionTypeEnum.SHARE,
        user_id=current_user.id,
        target_document_id=document.id,
        status_code=200
    )

    flash(f"Access granted to '{target_user.username}' for document '{document.title}'.", "success")
    return redirect(url_for('routes.dashboard'))

@routes_bp.route('/revoke/<int:doc_id>/<int:user_id>', methods=['POST', 'GET'])
@require_document_access(permission_type='revoke')
def revoke_document_access(doc_id: int, user_id: int):
    """
    Instantly revokes access to a document from a specific user.
    Database-backed state change guarantees immediate termination.
    """
    current_user = get_current_user()
    document = g.current_document

    share = DocumentShare.query.filter_by(
        document_id=document.id,
        user_id=user_id,
        is_active=True
    ).first()

    if not share:
        flash("No active share grant found for this user.", "warning")
        return redirect(url_for('routes.dashboard'))

    share.is_active = False
    share.revoked_at = datetime.now(timezone.utc)
    db.session.commit()

    # Record REVOKE in audit log
    record_audit_log(
        action_type=ActionTypeEnum.REVOKE,
        user_id=current_user.id,
        target_document_id=document.id,
        status_code=200
    )

    flash(f"Access instantly revoked for user ID {user_id}.", "info")
    return redirect(url_for('routes.dashboard'))

@routes_bp.route('/delete/<int:doc_id>', methods=['POST', 'DELETE', 'GET'])
@require_document_access(permission_type='delete')
def delete_document(doc_id: int):
    """
    Deletes a document.
    Server-side RBAC ensures ONLY the Document Owner can delete.
    Unauthorized attempts (e.g. from Viewers) are rejected with HTTP 403 Forbidden.
    """
    current_user = get_current_user()
    document = g.current_document

    stored_file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], document.stored_filename)
    if os.path.exists(stored_file_path):
        try:
            os.remove(stored_file_path)
        except OSError:
            pass

    doc_title = document.title
    db.session.delete(document)
    db.session.commit()

    # Record DELETE event in audit ledger
    record_audit_log(
        action_type=ActionTypeEnum.DELETE,
        user_id=current_user.id,
        target_document_id=doc_id,
        status_code=200
    )

    if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
        return jsonify({"message": f"Document {doc_id} successfully deleted", "status": 200}), 200

    flash(f"Document '{doc_title}' permanently deleted.", "info")
    return redirect(url_for('routes.dashboard'))
