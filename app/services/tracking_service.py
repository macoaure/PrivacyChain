"""
Service for tracking operations.

This module handles the business logic for indexing, unindexing, and managing tracking data.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.crud.tracking_crud import TrackingCRUD
from app.schemas.tracking import TrackingCreate
from app.services.anonymization_service import AnonymizationService
from app.services.blockchain_service import BlockchainService
from app.utils.enums import Blockchain as BlockchainEnum, HashMethod as HashMethodEnum
from app.config.settings import settings


class TrackingService:
    """
    Service class for tracking operations.

    Manages the lifecycle of tracking entries, including indexing and unindexing.
    """

    def __init__(self) -> None:
        self.blockchain_service = BlockchainService()

    def index_on_chain(self, db: Session, content: str, locator: str, hash_method: str = "SHA256") -> Dict[str, Any]:
        """
        Index data on the blockchain with simple anonymization.

        Args:
            db (Session): Database session.
            content (str): Content to index.
            locator (str): Entity locator.
            hash_method (str): Hash method to use.

        Returns:
            Dict[str, Any]: Created tracking entry.

        Raises:
            Exception: If indexing fails.
        """
        try:
            anonymized = AnonymizationService.simple_anonymize(content, hash_method)["content"]
            transaction = self.blockchain_service.register_on_chain(anonymized)
            transaction_id = transaction["transaction_id"]

            # Check if already exists
            existing = TrackingCRUD.get_tracking_by_transaction_id(db, transaction_id)
            if existing:
                raise Exception("Transaction already registered")

            tracking_data = TrackingCreate(
                canonical_data=content,
                anonymized_data=anonymized,
                blockchain_id=int(BlockchainEnum.ETHEREUM.value),
                transaction_id=transaction_id,
                salt="",
                hash_method=HashMethodEnum.SHA256.name,
                tracking_dt=datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                locator=locator
            )

            return TrackingCRUD.create_tracking(db, tracking_data).__dict__
        except Exception as e:
            raise Exception(f"Failed to index on chain: {str(e)}")

    def index_secure_on_chain(self, db: Session, content: str, locator: str, salt: str, hash_method: str = "SHA256") -> Dict[str, Any]:
        """
        Index data on the blockchain with secure anonymization.

        Args:
            db (Session): Database session.
            content (str): Content to index.
            locator (str): Entity locator.
            salt (str): Salt for anonymization.
            hash_method (str): Hash method.

        Returns:
            Dict[str, Any]: Created tracking entry.

        Raises:
            Exception: If indexing fails.
        """
        try:
            anonymized = AnonymizationService.secure_anonymize(content, salt, hash_method)["content"]
            transaction = self.blockchain_service.register_on_chain(anonymized)
            transaction_id = transaction["transaction_id"]

            existing = TrackingCRUD.get_tracking_by_transaction_id(db, transaction_id)
            if existing:
                raise Exception("Transaction already registered")

            tracking_data = TrackingCreate(
                canonical_data=content,
                anonymized_data=anonymized,
                blockchain_id=int(BlockchainEnum.ETHEREUM.value),
                transaction_id=transaction_id,
                salt=salt,
                hash_method=HashMethodEnum.SHA256.name,
                tracking_dt=datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
                locator=locator
            )

            return TrackingCRUD.create_tracking(db, tracking_data).__dict__
        except Exception as e:
            raise Exception(f"Failed to index secure on chain: {str(e)}")

    def unindex_on_chain(self, db: Session, locator: str, datetime_filter: Optional[str] = None) -> Dict[str, int]:
        """
        Unindex data from the blockchain.

        Args:
            db (Session): Database session.
            locator (str): Entity locator.
            datetime_filter (Optional[str]): Optional datetime filter.

        Returns:
            Dict[str, int]: Number of deleted entries.

        Raises:
            Exception: If no entries to unindex.
        """
        try:
            trackings = TrackingCRUD.get_trackings_for_unindex(db, locator, datetime_filter)
            if not trackings:
                raise Exception("Nothing to unindex")

            deleted_count = TrackingCRUD.delete_trackings_for_unindex(db, locator, datetime_filter)
            return {"deleted_count": deleted_count}
        except Exception as e:
            raise Exception(f"Failed to unindex on chain: {str(e)}")

    def rectify_on_chain(self, db: Session, content: str, salt: str, locator: str, datetime_filter: str, hash_method: str = "SHA256") -> Dict[str, Any]:
        """
        Rectify data on the blockchain.

        Args:
            db (Session): Database session.
            content (str): New content.
            salt (str): Salt.
            locator (str): Locator.
            datetime_filter (str): Datetime.
            hash_method (str): Hash method.

        Returns:
            Dict[str, Any]: New tracking entry.

        Raises:
            Exception: If rectification fails.
        """
        try:
            # Unindex old entries
            self.unindex_on_chain(db, locator, "")

            # Index new entry
            return self.index_secure_on_chain(db, content, locator, salt, hash_method)
        except Exception as e:
            raise Exception(f"Failed to rectify on chain: {str(e)}")

    def remove_on_chain(self, db: Session, locator: str, datetime_filter: str) -> Dict[str, int]:
        """
        Remove data from the blockchain (alias for unindex).

        Args:
            db (Session): Database session.
            locator (str): Locator.
            datetime_filter (str): Datetime.

        Returns:
            Dict[str, int]: Number of deleted entries.
        """
        return self.unindex_on_chain(db, locator, datetime_filter)
