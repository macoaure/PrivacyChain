"""
CRUD operations for proxy encryption models.

This module provides database operations for proxy keys, encrypted data,
and sharing records.
"""
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from datetime import datetime, timedelta

from app.models.proxy_encryption import ProxyKey, ShareRecord, EncryptedData, ReEncryptedData
from app.schemas.proxy_encryption import (
    ProxyKeyStorage, ShareRecord as ShareRecordSchema,
    ProxyShareMetrics
)


class ProxyKeyCRUD:
    """CRUD operations for proxy keys."""

    @staticmethod
    def create_proxy_key(db: Session, proxy_key_data: Dict[str, Any]) -> ProxyKey:
        """Create a new proxy key record."""
        proxy_key = ProxyKey(
            proxy_id=proxy_key_data["proxy_id"],
            locator=proxy_key_data["locator"],
            owner_public_key=proxy_key_data["owner_public_key"],
            recipient_public_key=proxy_key_data["recipient_public_key"],
            proxy_key_hash=proxy_key_data["proxy_key_hash"],
            proxy_data=proxy_key_data["proxy_data"],
            salt=proxy_key_data["salt"],
            expires_at=datetime.fromisoformat(proxy_key_data["expires_at"]),
            is_revoked=proxy_key_data.get("is_revoked", False)
        )
        db.add(proxy_key)
        db.commit()
        db.refresh(proxy_key)
        return proxy_key

    @staticmethod
    def get_proxy_key(db: Session, proxy_id: str) -> Optional[ProxyKey]:
        """Get a proxy key by ID."""
        return db.query(ProxyKey).filter(ProxyKey.proxy_id == proxy_id).first()

    @staticmethod
    def get_proxy_keys_by_locator(db: Session, locator: str) -> List[ProxyKey]:
        """Get all proxy keys for a specific locator."""
        return db.query(ProxyKey).filter(ProxyKey.locator == locator).all()

    @staticmethod
    def get_active_proxy_keys(db: Session, locator: str) -> List[ProxyKey]:
        """Get all active (non-revoked, non-expired) proxy keys for a locator."""
        now = datetime.utcnow()
        return db.query(ProxyKey).filter(
            and_(
                ProxyKey.locator == locator,
                ProxyKey.is_revoked == False,
                ProxyKey.expires_at > now
            )
        ).all()

    @staticmethod
    def revoke_proxy_key(db: Session, proxy_id: str) -> Optional[ProxyKey]:
        """Revoke a proxy key."""
        proxy_key = db.query(ProxyKey).filter(ProxyKey.proxy_id == proxy_id).first()
        if proxy_key:
            proxy_key.is_revoked = True
            proxy_key.revoked_at = datetime.utcnow()
            db.commit()
            db.refresh(proxy_key)
        return proxy_key

    @staticmethod
    def revoke_all_proxy_keys_for_locator(db: Session, locator: str, owner_public_key: str) -> int:
        """Revoke all proxy keys for a specific locator and owner."""
        count = db.query(ProxyKey).filter(
            and_(
                ProxyKey.locator == locator,
                ProxyKey.owner_public_key == owner_public_key,
                ProxyKey.is_revoked == False
            )
        ).update({
            "is_revoked": True,
            "revoked_at": datetime.utcnow()
        })
        db.commit()
        return count

    @staticmethod
    def cleanup_expired_proxy_keys(db: Session) -> int:
        """Clean up expired proxy keys (optional: mark as revoked)."""
        now = datetime.utcnow()
        count = db.query(ProxyKey).filter(
            and_(
                ProxyKey.expires_at <= now,
                ProxyKey.is_revoked == False
            )
        ).update({
            "is_revoked": True,
            "revoked_at": now
        })
        db.commit()
        return count


class EncryptedDataCRUD:
    """CRUD operations for encrypted data."""

    @staticmethod
    def create_encrypted_data(db: Session, encrypted_data: Dict[str, Any]) -> EncryptedData:
        """Create a new encrypted data record."""
        data = EncryptedData(
            encryption_id=encrypted_data["encryption_id"],
            locator=encrypted_data["locator"],
            owner_public_key=encrypted_data.get("owner_public_key", ""),
            encrypted_content=encrypted_data["encrypted_content"],
            iv=encrypted_data["iv"],
            encrypted_key=encrypted_data["encrypted_key"],
            key_hash=encrypted_data["key_hash"]
        )
        db.add(data)
        db.commit()
        db.refresh(data)
        return data

    @staticmethod
    def get_encrypted_data(db: Session, encryption_id: str) -> Optional[EncryptedData]:
        """Get encrypted data by ID."""
        return db.query(EncryptedData).filter(EncryptedData.encryption_id == encryption_id).first()

    @staticmethod
    def get_encrypted_data_by_locator(db: Session, locator: str) -> List[EncryptedData]:
        """Get all encrypted data for a specific locator."""
        return db.query(EncryptedData).filter(EncryptedData.locator == locator).all()


class ReEncryptedDataCRUD:
    """CRUD operations for re-encrypted data."""

    @staticmethod
    def create_re_encrypted_data(db: Session, re_encrypted_data: Dict[str, Any]) -> ReEncryptedData:
        """Create a new re-encrypted data record."""
        data = ReEncryptedData(
            re_encryption_id=re_encrypted_data["re_encryption_id"],
            original_encryption_id=re_encrypted_data["original_encryption_id"],
            proxy_id=re_encrypted_data["proxy_id"],
            locator=re_encrypted_data["locator"],
            recipient_public_key=re_encrypted_data["recipient_public_key"],
            re_encrypted_content=re_encrypted_data["re_encrypted_content"],
            iv=re_encrypted_data["iv"]
        )
        db.add(data)
        db.commit()
        db.refresh(data)
        return data

    @staticmethod
    def get_re_encrypted_data(db: Session, re_encryption_id: str) -> Optional[ReEncryptedData]:
        """Get re-encrypted data by ID."""
        return db.query(ReEncryptedData).filter(ReEncryptedData.re_encryption_id == re_encryption_id).first()

    @staticmethod
    def get_re_encrypted_data_by_proxy(db: Session, proxy_id: str) -> List[ReEncryptedData]:
        """Get all re-encrypted data for a specific proxy key."""
        return db.query(ReEncryptedData).filter(ReEncryptedData.proxy_id == proxy_id).all()


class ShareRecordCRUD:
    """CRUD operations for share records."""

    @staticmethod
    def create_share_record(db: Session, share_data: Dict[str, Any]) -> ShareRecord:
        """Create a new share record."""
        share = ShareRecord(
            share_id=share_data["share_id"],
            locator=share_data["locator"],
            owner_public_key=share_data["owner_public_key"],
            recipient_public_key=share_data["recipient_public_key"],
            encryption_id=share_data["encryption_id"],
            proxy_id=share_data["proxy_id"],
            re_encryption_id=share_data["re_encryption_id"],
            encrypted_data=share_data.get("encrypted_data"),
            re_encrypted_data=share_data.get("re_encrypted_data")
        )
        db.add(share)
        db.commit()
        db.refresh(share)
        return share

    @staticmethod
    def get_share_record(db: Session, share_id: str) -> Optional[ShareRecord]:
        """Get a share record by ID."""
        return db.query(ShareRecord).filter(ShareRecord.share_id == share_id).first()

    @staticmethod
    def get_shares_by_locator(db: Session, locator: str) -> List[ShareRecord]:
        """Get all share records for a specific locator."""
        return db.query(ShareRecord).filter(ShareRecord.locator == locator).all()

    @staticmethod
    def get_active_shares(db: Session, locator: str) -> List[ShareRecord]:
        """Get all active share records for a specific locator."""
        return db.query(ShareRecord).filter(
            and_(
                ShareRecord.locator == locator,
                ShareRecord.is_active == True
            )
        ).all()

    @staticmethod
    def deactivate_share(db: Session, share_id: str) -> Optional[ShareRecord]:
        """Deactivate a share record."""
        share = db.query(ShareRecord).filter(ShareRecord.share_id == share_id).first()
        if share:
            share.is_active = False
            db.commit()
            db.refresh(share)
        return share

    @staticmethod
    def deactivate_shares_by_proxy(db: Session, proxy_id: str) -> int:
        """Deactivate all shares using a specific proxy key."""
        count = db.query(ShareRecord).filter(
            and_(
                ShareRecord.proxy_id == proxy_id,
                ShareRecord.is_active == True
            )
        ).update({"is_active": False})
        db.commit()
        return count


class ProxyMetricsCRUD:
    """Operations for proxy encryption metrics."""

    @staticmethod
    def get_proxy_metrics(db: Session, locator: Optional[str] = None) -> ProxyShareMetrics:
        """Get proxy sharing metrics."""
        base_query = db.query(ProxyKey)

        if locator:
            base_query = base_query.filter(ProxyKey.locator == locator)

        total_shares = base_query.count()

        now = datetime.utcnow()
        active_shares = base_query.filter(
            and_(
                ProxyKey.is_revoked == False,
                ProxyKey.expires_at > now
            )
        ).count()

        revoked_shares = base_query.filter(ProxyKey.is_revoked == True).count()

        expired_shares = base_query.filter(
            and_(
                ProxyKey.is_revoked == False,
                ProxyKey.expires_at <= now
            )
        ).count()

        # Calculate average expiration time
        avg_expiration = db.query(
            func.avg(func.extract('epoch', ProxyKey.expires_at - ProxyKey.created_at) / 3600)
        ).filter(ProxyKey.locator == locator if locator else True).scalar()

        return ProxyShareMetrics(
            total_shares=total_shares,
            active_shares=active_shares,
            revoked_shares=revoked_shares,
            expired_shares=expired_shares,
            average_expiration_hours=avg_expiration or 0.0,
            locator=locator
        )
