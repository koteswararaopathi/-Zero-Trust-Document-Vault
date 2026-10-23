import os
import hashlib
from app import create_app
from app.models import db, User, Document, DocumentShare, AuditLog, RoleEnum, ActionTypeEnum
from app.audit import record_audit_log, verify_audit_integrity

app = create_app()

def seed_database():
    with app.app_context():
        db.create_all()

        # Seed Users if not present
        demo_users = [
            ("admin", "admin@trustvault.local", "AdminPass123!", RoleEnum.ADMIN.value),
            ("alice", "alice@trustvault.local", "AlicePass123!", RoleEnum.OWNER.value),
            ("bob", "bob@trustvault.local", "BobPass123!", RoleEnum.VIEWER.value),
            ("charlie", "charlie@trustvault.local", "CharliePass123!", RoleEnum.OWNER.value),
        ]

        created_users = {}
        for username, email, pwd, role in demo_users:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, email=email, role=role)
                user.set_password(pwd)
                db.session.add(user)
                db.session.commit()
                print(f"[SEED] Created user '{username}' with role '{role}'")
            created_users[username] = user

        # Create demo document for Alice if none exists
        alice = created_users.get('alice')
        if alice and alice.owned_documents.count() == 0:
            sample_content = b"TrustVault Confidential Architecture Specification v2.4.\nClassification: TOP SECRET."
            sample_hash = hashlib.sha256(sample_content).hexdigest()
            stored_filename = "demo_seed_doc_1.txt"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

            with open(file_path, "wb") as f:
                f.write(sample_content)

            demo_doc = Document(
                title="TrustVault System Architecture & Security Spec",
                original_filename="security_spec_2026.txt",
                stored_filename=stored_filename,
                file_size=len(sample_content),
                file_hash=sample_hash,
                mime_type="text/plain",
                owner_id=alice.id
            )
            db.session.add(demo_doc)
            db.session.commit()

            # Record write event in audit log
            record_audit_log(
                action_type=ActionTypeEnum.WRITE,
                user_id=alice.id,
                target_document_id=demo_doc.id,
                status_code=201
            )
            print(f"[SEED] Created initial sample document (ID {demo_doc.id}) for Alice")

        # Run integrity check
        check = verify_audit_integrity()
        print(f"[SEED] Audit Chain Status: {check.get('status')} ({check.get('count', 0)} entries)")

@app.cli.command("seed-db")
def seed_db_command():
    """Seeds demo users and documents."""
    seed_database()
    print("Database seeding completed.")

@app.cli.command("verify-audit")
def verify_audit_command():
    """Verifies cryptographic audit chain integrity from CLI."""
    with app.app_context():
        res = verify_audit_integrity()
        print(res)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed if empty
        if User.query.count() == 0:
            seed_database()
    app.run(host='127.0.0.1', port=5000, debug=True)
