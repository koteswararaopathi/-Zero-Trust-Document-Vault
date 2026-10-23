import logging
import pytest
from app.models import db, AuditLog, ActionTypeEnum
from app.audit import record_audit_log, verify_audit_integrity, calculate_entry_hash, GENESIS_HASH

def test_audit_cryptographic_chaining_positive(app, owner_user, viewer_user):
    """
    Verifies that audit log entries are chained sequentially with valid SHA-256 hashes.
    Each entry's prev_hash points to the prior entry_hash, and verify_audit_integrity() passes.
    """
    # Create several audit events
    log1 = record_audit_log(ActionTypeEnum.WRITE, user_id=owner_user.id, target_document_id=101, status_code=201)
    assert log1.prev_hash == GENESIS_HASH

    log2 = record_audit_log(ActionTypeEnum.SHARE, user_id=owner_user.id, target_document_id=101, status_code=200)
    assert log2.prev_hash == log1.entry_hash

    log3 = record_audit_log(ActionTypeEnum.READ, user_id=viewer_user.id, target_document_id=101, status_code=200)
    assert log3.prev_hash == log2.entry_hash

    # Verify integrity of entire chain
    result = verify_audit_integrity()
    assert result["valid"] is True
    assert result["status"] == "VERIFIED_SECURE"
    assert result["count"] == 3
    assert result["head_hash"] == log3.entry_hash
    assert result["genesis_hash"] == log1.entry_hash

def test_tamper_detection_action_type_altered(app, owner_user, caplog):
    """
    Negative test (Tamper check): Introduce an out-of-band edit to an audit row
    (action_type modified directly in database) -> Verify verify_audit_integrity()
    fails with a clear log alert.
    """
    record_audit_log(ActionTypeEnum.WRITE, user_id=owner_user.id, target_document_id=1)
    log2 = record_audit_log(ActionTypeEnum.READ, user_id=owner_user.id, target_document_id=1)
    record_audit_log(ActionTypeEnum.DELETE, user_id=owner_user.id, target_document_id=1)

    # Integrity passes before tampering
    assert verify_audit_integrity()["valid"] is True

    # Out-of-band malicious modification (e.g. via direct SQL update)
    with caplog.at_level(logging.CRITICAL):
        db.session.execute(
            db.update(AuditLog).where(AuditLog.id == log2.id).values(action_type="TAMPERED_ACTION")
        )
        db.session.commit()

        # Run verification utility
        result = verify_audit_integrity()

        # Must fail and identify tampered entry
        assert result["valid"] is False
        assert result["tampered_id"] == log2.id
        assert result["error_type"] == "DATA_TAMPERING_DETECTED"
        assert "Data tampering detected at record ID" in result["reason"]

        # Verify clear log alert was emitted
        assert any("AUDIT INTEGRITY ALERT: Data tampering detected" in r.message for r in caplog.records)

def test_tamper_detection_user_id_altered(app, owner_user, viewer_user, caplog):
    """
    Negative test (Tamper check): An attacker attempts to frame another user
    by altering user_id out-of-band -> verify_audit_integrity() detects tampering.
    """
    record_audit_log(ActionTypeEnum.READ, user_id=viewer_user.id, target_document_id=5)
    log_to_tamper = record_audit_log(ActionTypeEnum.DELETE, user_id=owner_user.id, target_document_id=5)

    with caplog.at_level(logging.CRITICAL):
        # Alter user_id directly in the database
        db.session.execute(
            db.update(AuditLog).where(AuditLog.id == log_to_tamper.id).values(user_id=viewer_user.id)
        )
        db.session.commit()

        result = verify_audit_integrity()
        assert result["valid"] is False
        assert result["tampered_id"] == log_to_tamper.id
        assert result["error_type"] == "DATA_TAMPERING_DETECTED"
        assert any("AUDIT INTEGRITY ALERT" in r.message for r in caplog.records)

def test_tamper_detection_broken_chain_prev_hash(app, owner_user, caplog):
    """
    Negative test (Tamper check): An attacker attempts to forge prev_hash.
    verify_audit_integrity() detects broken chain link.
    """
    record_audit_log(ActionTypeEnum.WRITE, user_id=owner_user.id, target_document_id=1)
    log2 = record_audit_log(ActionTypeEnum.READ, user_id=owner_user.id, target_document_id=1)
    log3 = record_audit_log(ActionTypeEnum.REVOKE, user_id=owner_user.id, target_document_id=1)

    with caplog.at_level(logging.CRITICAL):
        # Forge prev_hash on log3
        db.session.execute(
            db.update(AuditLog).where(AuditLog.id == log3.id).values(prev_hash="0" * 64)
        )
        db.session.commit()

        result = verify_audit_integrity()
        assert result["valid"] is False
        assert result["tampered_id"] == log3.id
        assert result["error_type"] == "BROKEN_CHAIN_LINK"
        assert any("AUDIT INTEGRITY ALERT: Chain broken" in r.message for r in caplog.records)

def test_tamper_detection_deleted_row(app, owner_user):
    """
    Negative test (Tamper check): An attacker deletes an intermediate audit log row
    to hide their activity -> verify_audit_integrity() detects missing link.
    """
    log1 = record_audit_log(ActionTypeEnum.WRITE, user_id=owner_user.id, target_document_id=1)
    log2 = record_audit_log(ActionTypeEnum.READ, user_id=owner_user.id, target_document_id=1)
    log3 = record_audit_log(ActionTypeEnum.DELETE, user_id=owner_user.id, target_document_id=1)

    # Delete log2 directly
    db.session.execute(db.delete(AuditLog).where(AuditLog.id == log2.id))
    db.session.commit()

    result = verify_audit_integrity()
    assert result["valid"] is False
    assert result["tampered_id"] == log3.id
    assert result["error_type"] == "BROKEN_CHAIN_LINK"

def test_api_verify_audit_endpoint(admin_client, owner_user):
    """
    Verifies that the /admin/verify-audit endpoint returns 200 with JSON payload
    when intact, and 409 when tampered.
    """
    record_audit_log(ActionTypeEnum.WRITE, user_id=owner_user.id, target_document_id=1)

    # Intact chain -> 200
    res = admin_client.get('/admin/verify-audit')
    assert res.status_code == 200
    data = res.get_json()
    assert data["valid"] is True

    # Tamper with the row
    log = AuditLog.query.first()
    log.action_type = "CORRUPTED"
    db.session.commit()

    # Tampered chain -> 409 Conflict
    tampered_res = admin_client.get('/admin/verify-audit')
    assert tampered_res.status_code == 409
    tampered_data = tampered_res.get_json()
    assert tampered_data["valid"] is False
    assert tampered_data["tampered_id"] == log.id
