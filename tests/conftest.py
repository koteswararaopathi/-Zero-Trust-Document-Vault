import os
import shutil
import hashlib
import pytest
from app import create_app
from app.config import TestConfig
from app.models import db, User, Document, DocumentShare, AuditLog, RoleEnum, ActionTypeEnum
from app.audit import record_audit_log

@pytest.fixture(scope='session')
def base_test_config():
    return TestConfig

@pytest.fixture
def app():
    app = create_app(TestConfig)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    # Clean up test upload directory
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        shutil.rmtree(app.config['UPLOAD_FOLDER'], ignore_errors=True)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def admin_user(app):
    user = User(username='admin', email='admin@test.local', role=RoleEnum.ADMIN.value)
    user.set_password('AdminSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def owner_user(app):
    user = User(username='alice', email='alice@test.local', role=RoleEnum.OWNER.value)
    user.set_password('AliceSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def viewer_user(app):
    user = User(username='bob', email='bob@test.local', role=RoleEnum.VIEWER.value)
    user.set_password('BobSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def other_owner_user(app):
    user = User(username='charlie', email='charlie@test.local', role=RoleEnum.OWNER.value)
    user.set_password('CharlieSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def admin_client(app, admin_user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_id'] = admin_user.id
    return c

@pytest.fixture
def owner_client(app, owner_user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_id'] = owner_user.id
    return c

@pytest.fixture
def viewer_client(app, viewer_user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_id'] = viewer_user.id
    return c

@pytest.fixture
def other_owner_client(app, other_owner_user):
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_id'] = other_owner_user.id
    return c

@pytest.fixture
def sample_document(app, owner_user):
    content = b"TOP SECRET: TrustVault Cryptographic Blueprint 2026."
    checksum = hashlib.sha256(content).hexdigest()
    stored_name = "test_blueprint.txt"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)

    with open(file_path, 'wb') as f:
        f.write(content)

    doc = Document(
        title="Classified Blueprint",
        original_filename="blueprint.txt",
        stored_filename=stored_name,
        file_size=len(content),
        file_hash=checksum,
        mime_type="text/plain",
        owner_id=owner_user.id
    )
    db.session.add(doc)
    db.session.commit()

    record_audit_log(
        action_type=ActionTypeEnum.WRITE,
        user_id=owner_user.id,
        target_document_id=doc.id,
        status_code=201
    )
    return doc
