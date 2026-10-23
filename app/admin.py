from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app.models import db, AuditLog, User, Document, RoleEnum
from app.rbac import require_role, get_current_user
from app.audit import verify_audit_integrity, calculate_entry_hash

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/audit-logs')
@require_role(RoleEnum.ADMIN)
def audit_logs():
    """
    Read-only audit stream for Administrators.
    Viewers and Owners are strictly denied access with HTTP 403.
    """
    user = get_current_user()
    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
    integrity_result = verify_audit_integrity()

    return render_template(
        'admin_audit.html',
        user=user,
        logs=logs,
        integrity=integrity_result
    )

@admin_bp.route('/verify-audit', methods=['GET', 'POST'])
@require_role(RoleEnum.ADMIN)
def api_verify_audit():
    """
    API endpoint running verify_audit_integrity() on demand.
    """
    result = verify_audit_integrity()
    return jsonify(result), (200 if result.get('valid') else 409)

@admin_bp.route('/simulate-tamper', methods=['POST'])
@require_role(RoleEnum.ADMIN)
def simulate_tamper():
    """
    Simulates an out-of-band malicious modification to demonstrate tamper detection.
    Alters a record's action_type or user_id directly in the DB without updating entry_hash.
    """
    target_id = request.form.get('log_id', type=int)
    log_entry = None
    if target_id:
        log_entry = db.session.get(AuditLog, target_id)
    else:
        log_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()

    if not log_entry:
        flash("No audit logs found to tamper with.", "warning")
        return redirect(url_for('admin.audit_logs'))

    # Tamper with the action type
    original_action = log_entry.action_type
    log_entry.action_type = "TAMPERED_ACTION" if original_action != "TAMPERED_ACTION" else "READ"
    db.session.commit()

    flash(
        f"Tamper simulated on AuditLog ID {log_entry.id}: Changed action '{original_action}' to '{log_entry.action_type}'. Run verification to detect!",
        "danger"
    )
    return redirect(url_for('admin.audit_logs'))

@admin_bp.route('/recalculate-chain', methods=['POST'])
@require_role(RoleEnum.ADMIN)
def recalculate_chain():
    """
    Recalculates the cryptographic chain hashes (used to restore chain after a test tamper).
    """
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()
    prev = "GENESIS"
    for log in logs:
        log.prev_hash = prev
        log.entry_hash = calculate_entry_hash(log.user_id, log.action_type, log.timestamp_str, prev)
        prev = log.entry_hash

    db.session.commit()
    flash("Audit chain cryptographically re-synchronized and restored.", "success")
    return redirect(url_for('admin.audit_logs'))
