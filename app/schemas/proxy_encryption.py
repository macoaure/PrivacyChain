"""
Pydantic schemas for proxy encryption operations.

This module defines the request and response models for proxy re-encryption endpoints.
"""
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime


class KeyPairResponse(BaseModel):
    """Response model for key pair generation."""
    private_key: str = Field(..., description="ECC private key in PEM format")
    public_key: str = Field(..., description="ECC public key in PEM format")


class EncryptForOwnerRequest(BaseModel):
    """Request model for owner encryption."""
    content: str = Field(..., description="Content to encrypt")
    owner_public_key: str = Field(..., description="Owner's public key in PEM format")
    locator: str = Field(..., description="Entity locator for tracking")


class EncryptForOwnerResponse(BaseModel):
    """Response model for owner encryption."""
    encrypted_content: str = Field(..., description="Base64 encoded encrypted content")
    iv: str = Field(..., description="Base64 encoded initialization vector")
    encrypted_key: str = Field(..., description="Base64 encoded encrypted AES key")
    key_hash: str = Field(..., description="Hash of the encryption key")
    locator: str = Field(..., description="Entity locator")
    timestamp: str = Field(..., description="Encryption timestamp")
    encryption_id: str = Field(..., description="Unique encryption identifier")


class GenerateProxyKeyRequest(BaseModel):
    """Request model for proxy key generation."""
    owner_private_key: str = Field(..., description="Owner's private key in PEM format")
    recipient_public_key: str = Field(..., description="Recipient's public key in PEM format")
    locator: str = Field(..., description="Entity locator")
    expiration_hours: int = Field(24, description="Hours until proxy key expires", ge=1, le=8760)


class ProxyKeyResponse(BaseModel):
    """Response model for proxy key generation."""
    proxy_id: str = Field(..., description="Unique proxy key identifier")
    proxy_key_hash: str = Field(..., description="Hash of the proxy key")
    locator: str = Field(..., description="Entity locator")
    owner_public_key: str = Field(..., description="Owner's public key")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    created_at: str = Field(..., description="Creation timestamp")
    expires_at: str = Field(..., description="Expiration timestamp")
    is_revoked: bool = Field(..., description="Revocation status")


class ReEncryptDataRequest(BaseModel):
    """Request model for data re-encryption."""
    encrypted_data: Dict[str, Any] = Field(..., description="Owner-encrypted data")
    proxy_key: Dict[str, Any] = Field(..., description="Valid proxy key")


class ReEncryptDataResponse(BaseModel):
    """Response model for data re-encryption."""
    re_encrypted_content: str = Field(..., description="Re-encrypted content for recipient")
    iv: str = Field(..., description="Base64 encoded initialization vector")
    proxy_id: str = Field(..., description="Proxy key identifier used")
    original_encryption_id: str = Field(..., description="Original encryption identifier")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    locator: str = Field(..., description="Entity locator")
    re_encrypted_at: str = Field(..., description="Re-encryption timestamp")
    re_encryption_id: str = Field(..., description="Unique re-encryption identifier")


class DecryptForRecipientRequest(BaseModel):
    """Request model for recipient decryption."""
    re_encrypted_data: Dict[str, Any] = Field(..., description="Re-encrypted data")
    recipient_private_key: str = Field(..., description="Recipient's private key in PEM format")


class DecryptForRecipientResponse(BaseModel):
    """Response model for recipient decryption."""
    decrypted_content: str = Field(..., description="Decrypted content")
    locator: str = Field(..., description="Entity locator")
    decrypted_at: str = Field(..., description="Decryption timestamp")


class RevokeProxyKeyRequest(BaseModel):
    """Request model for proxy key revocation."""
    proxy_key: Dict[str, Any] = Field(..., description="Proxy key to revoke")
    owner_private_key: str = Field(..., description="Owner's private key for authentication")


class RevokeProxyKeyResponse(BaseModel):
    """Response model for proxy key revocation."""
    revoked: bool = Field(..., description="Revocation status")


class VerifyProxyKeyRequest(BaseModel):
    """Request model for proxy key verification."""
    proxy_key: Dict[str, Any] = Field(..., description="Proxy key to verify")


class VerifyProxyKeyResponse(BaseModel):
    """Response model for proxy key verification."""
    valid: bool = Field(..., description="Validity status")
    reason: Optional[str] = Field(None, description="Reason if invalid")


class SecureShareRequest(BaseModel):
    """Request model for complete secure sharing workflow."""
    content: str = Field(..., description="Content to share")
    locator: str = Field(..., description="Entity locator")
    owner_private_key: str = Field(..., description="Owner's private key")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    expiration_hours: int = Field(24, description="Proxy key expiration time", ge=1, le=8760)


class SecureShareResponse(BaseModel):
    """Response model for complete secure sharing workflow."""
    share_id: str = Field(..., description="Unique share identifier")
    locator: str = Field(..., description="Entity locator")
    encrypted_data: Dict[str, Any] = Field(..., description="Owner-encrypted data")
    proxy_key: Dict[str, Any] = Field(..., description="Generated proxy key")
    re_encrypted_data: Dict[str, Any] = Field(..., description="Re-encrypted data for recipient")
    created_at: str = Field(..., description="Creation timestamp")


class ProxyKeyStorage(BaseModel):
    """Model for storing proxy keys in database."""
    proxy_id: str = Field(..., description="Unique proxy key identifier")
    locator: str = Field(..., description="Entity locator")
    owner_public_key: str = Field(..., description="Owner's public key")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    proxy_key_hash: str = Field(..., description="Hash of the proxy key")
    proxy_data: Dict[str, Any] = Field(..., description="Proxy key data")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: datetime = Field(..., description="Expiration timestamp")
    is_revoked: bool = Field(False, description="Revocation status")
    revoked_at: Optional[datetime] = Field(None, description="Revocation timestamp")
    salt: str = Field(..., description="Salt used in proxy key generation")


class ShareRecord(BaseModel):
    """Model for storing complete share records."""
    share_id: str = Field(..., description="Unique share identifier")
    locator: str = Field(..., description="Entity locator")
    owner_public_key: str = Field(..., description="Owner's public key")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    encryption_id: str = Field(..., description="Original encryption identifier")
    proxy_id: str = Field(..., description="Proxy key identifier")
    re_encryption_id: str = Field(..., description="Re-encryption identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    is_active: bool = Field(True, description="Whether share is still active")


class ProxyShareMetrics(BaseModel):
    """Model for proxy sharing metrics and analytics."""
    total_shares: int = Field(..., description="Total number of shares created")
    active_shares: int = Field(..., description="Number of active shares")
    revoked_shares: int = Field(..., description="Number of revoked shares")
    expired_shares: int = Field(..., description="Number of expired shares")
    average_expiration_hours: float = Field(..., description="Average expiration time")
    locator: Optional[str] = Field(None, description="Specific locator for metrics")
