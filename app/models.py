import enum
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class RoleEnum(str, enum.Enum):
    ADMIN = 'Admin'
    OWNER = 'Owner'
    VIEWER = 'Viewer'

class ActionTypeEnum(str, enum.Enum):
    READ = 'READ'
    WRITE = 'WRITE'
    SHARE = 'SHARE'
    REVOKE = 'REVOKE'
    DELETE = 'DELETE'
    ACCESS_DENIED = 'ACCESS_DENIED'

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=RoleEnum.VIEWER.value)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    owned_documents = db.relationship('Document', back_populates='owner', cascade='all, delete-orphan', lazy='dynamic')
    shares_received = db.relationship('DocumentShare', foreign_keys='DocumentShare.user_id', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', back_populates='user', lazy='dynamic')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == RoleEnum.ADMIN.value

    @property
    def is_owner(self) -> bool:
        return self.role == RoleEnum.OWNER.value

    @property
    def is_viewer(self) -> bool:
        return self.role == RoleEnum.VIEWER.value

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }

class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 content checksum
    mime_type = db.Column(db.String(100), default='application/octet-stream')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    owner = db.relationship('User', back_populates='owned_documents')
    shares = db.relationship('DocumentShare', back_populates='document', cascade='all, delete-orphan', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'mime_type': self.mime_type,
            'owner_id': self.owner_id,
            'owner_username': self.owner.username if self.owner else None,
            'created_at': self.created_at.isoformat()
        }

class DocumentShare(db.Model):
    __tablename__ = 'document_shares'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    granted_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)

    document = db.relationship('Document', back_populates='shares')
    user = db.relationship('User', foreign_keys=[user_id], back_populates='shares_received')
    granted_by = db.relationship('User', foreign_keys=[granted_by_id])

    __table_args__ = (
        db.UniqueConstraint('document_id', 'user_id', name='uq_doc_user_share'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'document_id': self.document_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'granted_by_id': self.granted_by_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None
        }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    timestamp_str = db.Column(db.String(35), nullable=False)  # Canonical ISO string used for hashing
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    target_document_id = db.Column(db.Integer, nullable=True, index=True)
    action_type = db.Column(db.String(32), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, default='127.0.0.1')
    status_code = db.Column(db.Integer, nullable=False, default=200)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False, index=True)

    user = db.relationship('User', back_populates='audit_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp_str,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'Anonymous/System',
            'target_document_id': self.target_document_id,
            'action_type': self.action_type,
            'ip_address': self.ip_address,
            'status_code': self.status_code,
            'prev_hash': self.prev_hash,
            'entry_hash': self.entry_hash
        }
