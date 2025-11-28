"""
API routes for secure sharing operations.

This module defines routes that integrate proxy re-encryption with existing
PrivacyChain operations for seamless secure data sharing.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from app.services.secure_sharing_service import SecureSharingService
from app.api.dependencies import get_db

router = APIRouter()


class IndexSecureWithSharingRequest(BaseModel):
    """Request model for secure indexing with optional sharing capability."""
    to_wallet: str = Field(..., description="Destination wallet address")
    from_wallet: str = Field(..., description="Source wallet address")
    content: str = Field(..., description="Content to anonymize and store")
    locator: str = Field(..., description="Entity locator")
    datetime: str = Field(..., description="Timestamp")
    salt: Optional[str] = Field(None, description="Salt for anonymization")
    owner_private_key: Optional[str] = Field(None, description="Owner's private key for sharing")
    enable_sharing: bool = Field(False, description="Whether to enable proxy re-encryption sharing")


class CreateShareRequest(BaseModel):
    """Request model for creating a data share."""
    locator: str = Field(..., description="Entity locator of data to share")
    owner_private_key: str = Field(..., description="Owner's private key")
    recipient_public_key: str = Field(..., description="Recipient's public key")
    expiration_hours: int = Field(24, description="Hours until share expires", ge=1, le=8760)


class RevokeShareRequest(BaseModel):
    """Request model for revoking a data share."""
    share_id: str = Field(..., description="Share identifier")
    owner_private_key: str = Field(..., description="Owner's private key for authentication")


class AccessShareRequest(BaseModel):
    """Request model for accessing shared data."""
    share_id: str = Field(..., description="Share identifier")
    recipient_private_key: str = Field(..., description="Recipient's private key")


@router.post('/indexSecureWithSharing/', tags=["Secure Sharing"])
def index_secure_with_sharing(
    data: IndexSecureWithSharingRequest,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Index data securely on blockchain with optional sharing capability.

    This endpoint extends the existing indexSecureOnChain functionality
    to optionally prepare data for secure sharing using proxy re-encryption.

    Args:
        data: Request data including content, locator, and sharing options.
        db: Database session.

    Returns:
        Dict containing transaction details and sharing capabilities.
    """
    try:
        result = SecureSharingService.index_secure_on_chain_with_sharing(
            db=db,
            content=data.content,
            locator=data.locator,
            salt=data.salt,
            owner_private_key=data.owner_private_key,
            enable_sharing=data.enable_sharing
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/createShare/', tags=["Secure Sharing"])
def create_share(
    data: CreateShareRequest,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Create a secure data share using proxy re-encryption.

    Generates a proxy key that allows the recipient to decrypt the shared data
    without exposing the owner's private key. The proxy key can be revoked at any time.

    Args:
        data: Share creation request.
        db: Database session.

    Returns:
        Dict containing share information and access details.
    """
    try:
        result = SecureSharingService.create_data_share(
            db=db,
            locator=data.locator,
            owner_private_key=data.owner_private_key,
            recipient_public_key=data.recipient_public_key,
            expiration_hours=data.expiration_hours
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/revokeShare/', tags=["Secure Sharing"])
def revoke_share(
    data: RevokeShareRequest,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Revoke a data share by invalidating the proxy key.

    Once revoked, the recipient will no longer be able to access the shared data.
    This demonstrates the "dismissible" nature of proxy keys.

    Args:
        data: Share revocation request.
        db: Database session.

    Returns:
        Dict indicating revocation status.
    """
    try:
        result = SecureSharingService.revoke_data_share(
            db=db,
            share_id=data.share_id,
            owner_private_key=data.owner_private_key
        )
        return {
            "share_id": data.share_id,
            "revoked": result["revoked"],
            "message": "Share successfully revoked",
            "blockchain_tx": result.get("blockchain_tx")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/accessShare/', tags=["Secure Sharing"])
def access_share(
    data: AccessShareRequest,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Access shared data using recipient's private key.

    Decrypts the shared data using the recipient's private key. This only works
    if the share is still active and the proxy key hasn't been revoked.

    Args:
        data: Share access request.
        db: Database session.

    Returns:
        Dict containing decrypted data.
    """
    try:
        result = SecureSharingService.get_shared_data(
            db=db,
            share_id=data.share_id,
            recipient_private_key=data.recipient_private_key
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/listShares/', tags=["Secure Sharing"])
def list_shares(
    locator: Optional[str] = None,
    owner_public_key: Optional[str] = None,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    List active data shares, optionally filtered by locator or owner.

    Args:
        locator: Optional locator to filter shares.
        owner_public_key: Optional owner public key to filter shares.
        db: Database session.

    Returns:
        Dict containing list of active shares.
    """
    try:
        result = SecureSharingService.list_active_shares(
            db=db,
            locator=locator,
            owner_public_key=owner_public_key
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/shareStatus/{share_id}', tags=["Secure Sharing"])
def get_share_status(
    share_id: str,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Get the status of a specific share.

    Args:
        share_id: Share identifier.
        db: Database session.

    Returns:
        Dict containing share status information.
    """
    try:
        from app.crud.proxy_encryption_crud import ShareRecordCRUD, ProxyKeyCRUD
        from datetime import datetime

        # Get share record
        share_record = ShareRecordCRUD.get_share_record(db, share_id)
        if not share_record:
            raise HTTPException(status_code=404, detail="Share not found")

        # Get proxy key details
        proxy_key = ProxyKeyCRUD.get_proxy_key(db, share_record.proxy_id)

        now = datetime.utcnow()
        is_expired = proxy_key and now > proxy_key.expires_at
        is_revoked = proxy_key and proxy_key.is_revoked
        is_active = share_record.is_active and not is_expired and not is_revoked

        return {
            "share_id": share_id,
            "locator": share_record.locator,
            "is_active": is_active,
            "is_revoked": is_revoked,
            "is_expired": is_expired,
            "created_at": share_record.created_at.isoformat(),
            "expires_at": proxy_key.expires_at.isoformat() if proxy_key else None,
            "recipient_public_key": share_record.recipient_public_key,
            "proxy_id": share_record.proxy_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete('/revokeAllShares/{locator}', tags=["Secure Sharing"])
def revoke_all_shares_for_locator(
    locator: str,
    owner_public_key: str,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Revoke all active shares for a specific locator.

    This is useful when you want to immediately revoke access to all
    shared instances of a particular data item.

    Args:
        locator: Entity locator.
        owner_public_key: Owner's public key for verification.
        db: Database session.

    Returns:
        Dict with revocation results.
    """
    try:
        from app.crud.proxy_encryption_crud import ProxyKeyCRUD

        # Revoke all proxy keys for this locator
        count = ProxyKeyCRUD.revoke_all_proxy_keys_for_locator(db, locator, owner_public_key)

        # Also deactivate related share records
        from app.crud.proxy_encryption_crud import ShareRecordCRUD
        active_shares = ShareRecordCRUD.get_active_shares(db, locator)
        deactivated_count = 0

        for share in active_shares:
            ShareRecordCRUD.deactivate_share(db, share.share_id)
            deactivated_count += 1

        return {
            "locator": locator,
            "revoked_proxy_keys": count,
            "deactivated_shares": deactivated_count,
            "message": f"Revoked {count} proxy keys and deactivated {deactivated_count} shares for locator {locator}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))"
