"""
Service for integrating proxy re-encryption with existing PrivacyChain operations.

This module extends the existing tracking service to support proxy re-encryption
for secure data sharing while maintaining compatibility with existing flows.
"""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.services.proxy_encryption_service import ProxyEncryptionService
from app.services.anonymization_service import AnonymizationService
from app.services.blockchain_service import BlockchainService
from app.services.tracking_service import TrackingService
from app.crud.proxy_encryption_crud import ProxyKeyCRUD, ShareRecordCRUD, EncryptedDataCRUD
from app.crud.tracking_crud import TrackingCRUD
from web3 import Web3


class SecureSharingService:
    """
    Service class for secure data sharing with proxy re-encryption.

    Integrates proxy re-encryption capabilities with existing PrivacyChain
    anonymization and blockchain operations.
    """

    @staticmethod
    def index_secure_on_chain_with_sharing(
        db: Session,
        content: str,
        locator: str,
        salt: Optional[str] = None,
        owner_private_key: Optional[str] = None,
        enable_sharing: bool = False
    ) -> Dict[str, Any]:
        """
        Enhanced version of index_secure_on_chain that optionally supports sharing.

        Args:
            db: Database session.
            content: Content to anonymize and store.
            locator: Entity locator.
            salt: Salt for anonymization (optional).
            owner_private_key: Owner's private key for sharing (optional).
            enable_sharing: Whether to enable proxy re-encryption sharing.

        Returns:
            Dict containing transaction details and sharing capabilities.
        """
        # Use existing tracking service for core functionality
        tracking_service = TrackingService()
        result = tracking_service.index_secure_on_chain(db, content, locator, salt)

        if enable_sharing and owner_private_key:
            try:
                # Generate owner key pair if not provided
                owner_key = ProxyEncryptionService.generate_key_pair()
                if not owner_private_key:
                    owner_private_key = owner_key["private_key"]

                # Encrypt content for owner (for sharing purposes)
                owner_public_key = ProxyEncryptionService.generate_key_pair()["public_key"]
                if owner_private_key:
                    # Extract public key from private key
                    from Crypto.PublicKey import ECC
                    key = ECC.import_key(owner_private_key)
                    owner_public_key = key.public_key().export_key(format='PEM')

                encrypted_data = ProxyEncryptionService.encrypt_for_owner(
                    content, owner_public_key, locator
                )

                # Store encrypted data
                EncryptedDataCRUD.create_encrypted_data(db, encrypted_data)

                # Add sharing information to result
                result.update({
                    "sharing_enabled": True,
                    "owner_public_key": owner_public_key,
                    "encryption_id": encrypted_data["encryption_id"],
                    "sharing_ready": True
                })

            except Exception as e:
                # Don't fail the entire operation if sharing setup fails
                result.update({
                    "sharing_enabled": False,
                    "sharing_error": str(e)
                })
        else:
            result.update({
                "sharing_enabled": False
            })

        return result

    @staticmethod
    def create_data_share(
        db: Session,
        locator: str,
        owner_private_key: str,
        recipient_public_key: str,
        expiration_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Create a secure data share using proxy re-encryption.

        Args:
            db: Database session.
            locator: Entity locator of data to share.
            owner_private_key: Owner's private key.
            recipient_public_key: Recipient's public key.
            expiration_hours: Hours until share expires.

        Returns:
            Dict containing share information.
        """
        # Find existing tracking record
        tracking_records = TrackingCRUD.get_tracking_by_locator(db, locator)
        if not tracking_records:
            raise Exception(f"No data found for locator: {locator}")

        # Get the latest record
        latest_record = tracking_records[0]

        # Check if encrypted data already exists for this locator
        encrypted_records = EncryptedDataCRUD.get_encrypted_data_by_locator(db, locator)

        if not encrypted_records:
            # Need to create encrypted version from canonical data
            owner_key = ProxyEncryptionService.generate_key_pair()
            if owner_private_key:
                from Crypto.PublicKey import ECC
                key = ECC.import_key(owner_private_key)
                owner_public_key = key.public_key().export_key(format='PEM')
            else:
                owner_public_key = owner_key["public_key"]
                owner_private_key = owner_key["private_key"]

            # Encrypt the canonical data
            encrypted_data = ProxyEncryptionService.encrypt_for_owner(
                latest_record.canonical_data, owner_public_key, locator
            )
            EncryptedDataCRUD.create_encrypted_data(db, encrypted_data)
        else:
            encrypted_data = {
                "encryption_id": encrypted_records[0].encryption_id,
                "encrypted_content": encrypted_records[0].encrypted_content,
                "iv": encrypted_records[0].iv,
                "encrypted_key": encrypted_records[0].encrypted_key,
                "key_hash": encrypted_records[0].key_hash,
                "locator": locator,
                "timestamp": encrypted_records[0].created_at.isoformat()
            }

        # Generate proxy key
        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_private_key, recipient_public_key, locator, expiration_hours
        )

        # Store proxy key
        ProxyKeyCRUD.create_proxy_key(db, proxy_key)

        # Re-encrypt data
        re_encrypted_data = ProxyEncryptionService.re_encrypt_data(
            encrypted_data, proxy_key
        )

        # Store re-encrypted data
        from app.crud.proxy_encryption_crud import ReEncryptedDataCRUD
        ReEncryptedDataCRUD.create_re_encrypted_data(db, re_encrypted_data)

        # Create share record
        share_data = {
            "share_id": str(uuid.uuid4()),
            "locator": locator,
            "owner_public_key": proxy_key["owner_public_key"],
            "recipient_public_key": recipient_public_key,
            "encryption_id": encrypted_data.get("encryption_id", ""),
            "proxy_id": proxy_key["proxy_id"],
            "re_encryption_id": re_encrypted_data["re_encryption_id"]
        }

        import uuid
        ShareRecordCRUD.create_share_record(db, share_data)

        # Register on blockchain if available
        try:
            blockchain_service = BlockchainService()
            data_id = Web3.keccak(text=locator).hex()

            # Register data if not already registered
            try:
                blockchain_service.register_proxy_data(data_id)
            except:
                pass  # Might already be registered

            # Generate proxy key on blockchain
            expires_at = datetime.fromisoformat(proxy_key["expires_at"])
            expiration_timestamp = int(expires_at.timestamp())

            # Simplified recipient address (in practice, derive from public key)
            recipient_address = "0x" + recipient_public_key[-40:]

            tx_hash = blockchain_service.generate_proxy_key_on_chain(
                proxy_key["proxy_id"],
                data_id,
                recipient_address,
                proxy_key["proxy_key_hash"],
                expiration_timestamp
            )

            share_data["blockchain_tx"] = tx_hash

        except Exception as e:
            # Don't fail the operation if blockchain registration fails
            share_data["blockchain_error"] = str(e)

        return {
            "share_id": share_data["share_id"],
            "locator": locator,
            "proxy_id": proxy_key["proxy_id"],
            "recipient_public_key": recipient_public_key,
            "expires_at": proxy_key["expires_at"],
            "re_encrypted_data": re_encrypted_data,
            "share_created_at": datetime.utcnow().isoformat(),
            "blockchain_tx": share_data.get("blockchain_tx")
        }

    @staticmethod
    def revoke_data_share(
        db: Session,
        share_id: str,
        owner_private_key: str
    ) -> Dict[str, bool]:
        """
        Revoke a data share by revoking the proxy key.

        Args:
            db: Database session.
            share_id: Share identifier.
            owner_private_key: Owner's private key for authentication.

        Returns:
            Dict indicating revocation status.
        """
        # Find share record
        share_record = ShareRecordCRUD.get_share_record(db, share_id)
        if not share_record:
            raise Exception("Share record not found")

        # Get proxy key
        proxy_key_record = ProxyKeyCRUD.get_proxy_key(db, share_record.proxy_id)
        if not proxy_key_record:
            raise Exception("Proxy key not found")

        # Convert to dict format for service
        proxy_key_dict = {
            "proxy_id": proxy_key_record.proxy_id,
            "owner_public_key": proxy_key_record.owner_public_key,
            "is_revoked": proxy_key_record.is_revoked
        }

        # Revoke proxy key
        result = ProxyEncryptionService.revoke_proxy_key(proxy_key_dict, owner_private_key)

        # Update database
        ProxyKeyCRUD.revoke_proxy_key(db, proxy_key_record.proxy_id)
        ShareRecordCRUD.deactivate_share(db, share_id)

        # Revoke on blockchain
        try:
            blockchain_service = BlockchainService()
            tx_hash = blockchain_service.revoke_proxy_key_on_chain(proxy_key_record.proxy_id)
            result["blockchain_tx"] = tx_hash
        except Exception as e:
            result["blockchain_error"] = str(e)

        return result

    @staticmethod
    def get_shared_data(
        db: Session,
        share_id: str,
        recipient_private_key: str
    ) -> Dict[str, Any]:
        """
        Retrieve and decrypt shared data using recipient's private key.

        Args:
            db: Database session.
            share_id: Share identifier.
            recipient_private_key: Recipient's private key.

        Returns:
            Dict containing decrypted data.
        """
        # Find share record
        share_record = ShareRecordCRUD.get_share_record(db, share_id)
        if not share_record:
            raise Exception("Share record not found")

        if not share_record.is_active:
            raise Exception("Share has been deactivated")

        # Check if proxy key is still valid
        proxy_key_record = ProxyKeyCRUD.get_proxy_key(db, share_record.proxy_id)
        if not proxy_key_record or proxy_key_record.is_revoked:
            raise Exception("Proxy key has been revoked")

        if datetime.utcnow() > proxy_key_record.expires_at:
            raise Exception("Proxy key has expired")

        # Get re-encrypted data
        from app.crud.proxy_encryption_crud import ReEncryptedDataCRUD
        re_encrypted_records = ReEncryptedDataCRUD.get_re_encrypted_data_by_proxy(db, share_record.proxy_id)

        if not re_encrypted_records:
            raise Exception("Re-encrypted data not found")

        re_encrypted_data = {
            "re_encrypted_content": re_encrypted_records[0].re_encrypted_content,
            "iv": re_encrypted_records[0].iv,
            "locator": re_encrypted_records[0].locator,
            "re_encryption_id": re_encrypted_records[0].re_encryption_id
        }

        # Decrypt data
        decrypted_result = ProxyEncryptionService.decrypt_for_recipient(
            re_encrypted_data, recipient_private_key
        )

        return {
            "share_id": share_id,
            "locator": share_record.locator,
            "decrypted_content": decrypted_result["decrypted_content"],
            "accessed_at": datetime.utcnow().isoformat(),
            "proxy_id": share_record.proxy_id
        }

    @staticmethod
    def list_active_shares(
        db: Session,
        locator: Optional[str] = None,
        owner_public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List all active shares, optionally filtered by locator or owner.

        Args:
            db: Database session.
            locator: Optional locator filter.
            owner_public_key: Optional owner filter.

        Returns:
            Dict containing list of active shares.
        """
        if locator:
            shares = ShareRecordCRUD.get_active_shares(db, locator)
        else:
            # Get all active shares (would need to implement this in CRUD)
            shares = []

        result = {
            "total_shares": len(shares),
            "locator_filter": locator,
            "shares": []
        }

        for share in shares:
            # Get proxy key details
            proxy_key = ProxyKeyCRUD.get_proxy_key(db, share.proxy_id)

            if owner_public_key and proxy_key and proxy_key.owner_public_key != owner_public_key:
                continue

            share_info = {
                "share_id": share.share_id,
                "locator": share.locator,
                "recipient_public_key": share.recipient_public_key,
                "created_at": share.created_at.isoformat(),
                "expires_at": proxy_key.expires_at.isoformat() if proxy_key else None,
                "is_active": share.is_active and (not proxy_key or not proxy_key.is_revoked)
            }
            result["shares"].append(share_info)

        return result
