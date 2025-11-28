"""
Database models for proxy encryption.

This module defines SQLAlchemy models for storing proxy keys and sharing records.
"""
from sqlalchemy import Column, String, DateTime, Boolean, Text, Integer
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSON
from app.database.connection import Base


class ProxyKey(Base):
    """
    Model for storing proxy keys in the database.

    Tracks proxy keys generated for data sharing with their metadata,
    expiration times, and revocation status.
    """
    __tablename__ = "proxy_keys"

    proxy_id = Column(String, primary_key=True, index=True)
    locator = Column(String, nullable=False, index=True)
    owner_public_key = Column(Text, nullable=False)
    recipient_public_key = Column(Text, nullable=False)
    proxy_key_hash = Column(String, nullable=False, unique=True)
    proxy_data = Column(JSON, nullable=False)
    salt = Column(String, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<ProxyKey(proxy_id={self.proxy_id}, locator={self.locator}, revoked={self.is_revoked})>"


class ShareRecord(Base):
    """
    Model for storing complete sharing transactions.

    Records the complete sharing workflow including original encryption,
    proxy key generation, and re-encryption details.
    """
    __tablename__ = "share_records"

    share_id = Column(String, primary_key=True, index=True)
    locator = Column(String, nullable=False, index=True)
    owner_public_key = Column(Text, nullable=False)
    recipient_public_key = Column(Text, nullable=False)

    # References to related records
    encryption_id = Column(String, nullable=False)
    proxy_id = Column(String, nullable=False)
    re_encryption_id = Column(String, nullable=False)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Optional: store encrypted data directly (for performance)
    encrypted_data = Column(JSON, nullable=True)
    re_encrypted_data = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ShareRecord(share_id={self.share_id}, locator={self.locator}, active={self.is_active})>"


class EncryptedData(Base):
    """
    Model for storing owner-encrypted data.

    Stores the original encrypted data before proxy re-encryption.
    """
    __tablename__ = "encrypted_data"

    encryption_id = Column(String, primary_key=True, index=True)
    locator = Column(String, nullable=False, index=True)
    owner_public_key = Column(Text, nullable=False)

    # Encrypted content and metadata
    encrypted_content = Column(Text, nullable=False)
    iv = Column(String, nullable=False)
    encrypted_key = Column(Text, nullable=False)
    key_hash = Column(String, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<EncryptedData(encryption_id={self.encryption_id}, locator={self.locator})>"


class ReEncryptedData(Base):
    """
    Model for storing re-encrypted data for recipients.

    Stores the transformed encrypted data that recipients can decrypt.
    """
    __tablename__ = "re_encrypted_data"

    re_encryption_id = Column(String, primary_key=True, index=True)
    original_encryption_id = Column(String, nullable=False)
    proxy_id = Column(String, nullable=False)
    locator = Column(String, nullable=False, index=True)
    recipient_public_key = Column(Text, nullable=False)

    # Re-encrypted content and metadata
    re_encrypted_content = Column(Text, nullable=False)
    iv = Column(String, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"<ReEncryptedData(re_encryption_id={self.re_encryption_id}, proxy_id={self.proxy_id})>"
