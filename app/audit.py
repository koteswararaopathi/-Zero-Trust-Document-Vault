import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask import request, has_request_context
from app.models import db, AuditLog, ActionTypeEnum

logger = logging.getLogger("trustvault.audit")
logging.basicConfig(level=logging.INFO)

GENESIS_HASH = "GENESIS"

def calculate_entry_hash(
    user_id: Optional[int],
    action_type: str,
    timestamp_str: str,
    prev_hash: str
) -> str:
    """
    Computes cryptographic SHA-256 hash chaining:
    Hash input: user_id + action + timestamp + prev_hash
    """
    canonical_user_id = str(user_id) if user_id is not None else "None"
    payload = f"{canonical_user_id}|{action_type}|{timestamp_str}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def record_audit_log(
    action_type: str,
    user_id: Optional[int] = None,
    target_document_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    status_code: int = 200,
    commit: bool = True
) -> AuditLog:
    """
    Appends a new cryptographically chained audit log entry to the immutable ledger.
    """
    if isinstance(action_type, ActionTypeEnum):
        action_type = action_type.value

    # Determine previous hash from latest log entry
    last_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH

    now = datetime.now(timezone.utc)
    timestamp_str = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    resolved_ip = ip_address
    if not resolved_ip and has_request_context():
        # Respect X-Forwarded-For if behind proxy, fallback to remote_addr
        forwarded = request.headers.get('X-Forwarded-For')
        resolved_ip = forwarded.split(',')[0].strip() if forwarded else request.remote_addr
    if not resolved_ip:
        resolved_ip = '127.0.0.1'

    entry_hash = calculate_entry_hash(
        user_id=user_id,
        action_type=action_type,
        timestamp_str=timestamp_str,
        prev_hash=prev_hash
    )

    log_entry = AuditLog(
        timestamp=now,
        timestamp_str=timestamp_str,
        user_id=user_id,
        target_document_id=target_document_id,
        action_type=action_type,
        ip_address=resolved_ip,
        status_code=status_code,
        prev_hash=prev_hash,
        entry_hash=entry_hash
    )

    db.session.add(log_entry)
    if commit:
        db.session.commit()

    logger.info(
        f"[AUDIT] id={log_entry.id} action={action_type} user_id={user_id} "
        f"doc_id={target_document_id} status={status_code} hash={entry_hash[:12]}..."
    )
    return log_entry

def verify_audit_integrity() -> Dict[str, Any]:
    """
    Traverses the cryptographic audit chain and verifies integrity.
    Detects any out-of-band database modifications or broken chaining links.
    """
    logs = AuditLog.query.order_by(AuditLog.id.asc()).all()

    if not logs:
        return {
            "valid": True,
            "count": 0,
            "status": "EMPTY_CHAIN",
            "message": "Audit chain is empty. No records to verify."
        }

    expected_prev_hash = GENESIS_HASH

    for index, entry in enumerate(logs):
        # 1. Verify previous hash chaining link
        if entry.prev_hash != expected_prev_hash:
            msg = (
                f"AUDIT INTEGRITY ALERT: Chain broken at record ID {entry.id}. "
                f"Expected prev_hash '{expected_prev_hash}', found '{entry.prev_hash}'."
            )
            logger.critical(msg)
            return {
                "valid": False,
                "tampered_id": entry.id,
                "error_type": "BROKEN_CHAIN_LINK",
                "reason": msg,
                "inspected_records": index,
                "total_records": len(logs)
            }

        # 2. Recalculate and verify entry hash
        recalculated_hash = calculate_entry_hash(
            user_id=entry.user_id,
            action_type=entry.action_type,
            timestamp_str=entry.timestamp_str,
            prev_hash=entry.prev_hash
        )

        if entry.entry_hash != recalculated_hash:
            msg = (
                f"AUDIT INTEGRITY ALERT: Data tampering detected at record ID {entry.id}! "
                f"Stored hash '{entry.entry_hash}' does not match calculated hash '{recalculated_hash}'. "
                f"Row contents (user_id={entry.user_id}, action={entry.action_type}, timestamp={entry.timestamp_str}) "
                f"were altered out-of-band."
            )
            logger.critical(msg)
            return {
                "valid": False,
                "tampered_id": entry.id,
                "error_type": "DATA_TAMPERING_DETECTED",
                "reason": msg,
                "inspected_records": index,
                "total_records": len(logs)
            }

        expected_prev_hash = entry.entry_hash

    return {
        "valid": True,
        "count": len(logs),
        "status": "VERIFIED_SECURE",
        "head_hash": logs[-1].entry_hash,
        "genesis_hash": logs[0].entry_hash,
        "message": f"Successfully verified {len(logs)} audit log records. Chain is intact and immutable."
    }
