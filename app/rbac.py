from functools import wraps
from typing import List, Callable, Any
from flask import session, request, abort, redirect, url_for, flash, g, jsonify
from app.models import db, User, Document, DocumentShare, RoleEnum, ActionTypeEnum
from app.audit import record_audit_log

def get_current_user() -> User | None:
    """
    Retrieves the authenticated user from the database based on the secure session.
    Validates that any cached user in g matches the current request's session user_id.
    """
    user_id = session.get('user_id')
    if not user_id:
        g.current_user = None
        return None

    cached = getattr(g, 'current_user', None)
    if cached is not None and getattr(cached, 'id', None) == user_id:
        return cached

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        g.current_user = None
        return None

    g.current_user = user
    return user

def require_role(*roles: str | RoleEnum) -> Callable:
    """
    Decorator verifying that the authenticated user possesses one of the specified roles.
    Rejects unauthorized access with HTTP 403 Forbidden.
    """
    # Normalize roles to string values
    allowed_roles = {r.value if isinstance(r, RoleEnum) else str(r) for r in roles}

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_user = get_current_user()

            if not current_user:
                if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('auth.login', next=request.path))

            if current_user.role not in allowed_roles:
                # Log security access violation
                record_audit_log(
                    action_type=ActionTypeEnum.ACCESS_DENIED,
                    user_id=current_user.id,
                    target_document_id=kwargs.get('doc_id') or kwargs.get('document_id'),
                    status_code=403
                )
                if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                    return jsonify({"error": "Forbidden", "message": f"Role '{current_user.role}' not permitted"}), 403
                abort(403, description=f"Access denied: Role '{current_user.role}' lacks sufficient privileges.")

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def require_document_access(permission_type: str = 'read') -> Callable:
    """
    Decorator intercepting requests targeting document IDs:
    (/download/<doc_id>, /share/<doc_id>, /revoke/<doc_id>, /delete/<doc_id>)

    Verifies database ownership and active grants before returning any data.
    Enforces server-side RBAC and eliminates IDOR vulnerabilities:
    - Rejects unauthorized users with HTTP 403 Forbidden.
    - Records ACCESS_DENIED in the immutable audit ledger.
    - Ensures instantaneous revocation.
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_user = get_current_user()

            if not current_user:
                if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
                flash("Please log in to continue.", "warning")
                return redirect(url_for('auth.login', next=request.path))

            # Resolve document ID from URL kwargs or query parameters
            doc_id = kwargs.get('doc_id') or kwargs.get('document_id')
            if doc_id is None:
                doc_id = request.args.get('doc_id', type=int)

            if doc_id is None:
                abort(400, description="Missing document ID")

            document = db.session.get(Document, doc_id)
            if not document:
                # To prevent enumeration while being explicit
                record_audit_log(
                    action_type=ActionTypeEnum.ACCESS_DENIED,
                    user_id=current_user.id,
                    target_document_id=doc_id,
                    status_code=404
                )
                abort(404, description="Document not found")

            # Check permissions based on permission_type
            normalized_perm = permission_type.lower()
            has_permission = False

            if normalized_perm in ('write', 'share', 'revoke', 'delete'):
                # ONLY the document owner has management rights (delete, share, revoke)
                # Admins have audit-only oversight, Viewers strictly read-only
                if document.owner_id == current_user.id:
                    has_permission = True
                else:
                    has_permission = False

            elif normalized_perm == 'read':
                # Document Owner always has read access
                if document.owner_id == current_user.id:
                    has_permission = True
                elif current_user.is_admin:
                    # Admin oversight
                    has_permission = True
                else:
                    # Check active grant in DocumentShare for Viewers
                    # Real-time DB lookup ensures instantaneous revocation
                    active_share = DocumentShare.query.filter_by(
                        document_id=document.id,
                        user_id=current_user.id,
                        is_active=True
                    ).first()
                    has_permission = active_share is not None
            else:
                abort(500, description=f"Unknown permission type: {permission_type}")

            if not has_permission:
                # Log security alert in tamper-resistant audit trail
                record_audit_log(
                    action_type=ActionTypeEnum.ACCESS_DENIED,
                    user_id=current_user.id,
                    target_document_id=document.id,
                    status_code=403
                )
                if request.is_json or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
                    return jsonify({
                        "error": "Forbidden",
                        "message": f"You do not have '{permission_type}' permission for document {doc_id}."
                    }), 403
                abort(403, description=f"Access Denied: You do not have '{permission_type}' permission on this document.")

            # Attach document to request context for clean controller usage
            g.current_document = document
            return fn(*args, **kwargs)

        return wrapper
    return decorator
