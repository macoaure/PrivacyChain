"""
CRUD operations for tracking data.

This module provides functions to create, read, update, and delete tracking entries.
"""
from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.tracking import Tracking
from app.schemas.tracking import TrackingCreate


class TrackingCRUD:
    """
    Class for tracking CRUD operations.

    This class encapsulates all database operations related to tracking data.
    """

    @staticmethod
    def get_tracking_by_id(db: Session, tracking_id: int) -> Optional[Tracking]:
        """
        Retrieve a tracking entry by its ID.

        Args:
            db (Session): Database session.
            tracking_id (int): The tracking ID to search for.

        Returns:
            Optional[Tracking]: The tracking entry if found, None otherwise.
        """
        return db.query(Tracking).filter(Tracking.tracking_id == tracking_id).first()

    @staticmethod
    def get_tracking_by_transaction_id(db: Session, transaction_id: str) -> Optional[Tracking]:
        """
        Retrieve a tracking entry by transaction ID.

        Args:
            db (Session): Database session.
            transaction_id (str): The transaction ID to search for.

        Returns:
            Optional[Tracking]: The tracking entry if found, None otherwise.
        """
        return db.query(Tracking).filter(Tracking.transaction_id == transaction_id).first()

    @staticmethod
    def get_trackings(db: Session, skip: int = 0, limit: int = 100) -> List[Tracking]:
        """
        Retrieve a list of tracking entries.

        Args:
            db (Session): Database session.
            skip (int): Number of entries to skip.
            limit (int): Maximum number of entries to return.

        Returns:
            List[Tracking]: List of tracking entries.
        """
        return db.query(Tracking).offset(skip).limit(limit).all()

    @staticmethod
    def create_tracking(db: Session, tracking: TrackingCreate) -> Tracking:
        """
        Create a new tracking entry.

        Args:
            db (Session): Database session.
            tracking (TrackingCreate): The tracking data to create.

        Returns:
            Tracking: The created tracking entry.
        """
        db_tracking = Tracking(
            canonical_data=tracking.canonical_data,
            anonymized_data=tracking.anonymized_data,
            blockchain_id=tracking.blockchain_id,
            transaction_id=tracking.transaction_id,
            salt=tracking.salt,
            hash_method=tracking.hash_method,
            tracking_dt=tracking.tracking_dt,
            locator=tracking.locator
        )
        db.add(db_tracking)
        db.commit()
        db.refresh(db_tracking)
        return db_tracking

    @staticmethod
    def get_trackings_for_unindex(db: Session, locator: str, datetime_filter: Optional[str] = None) -> List[Tracking]:
        """
        Get tracking entries for unindexing based on locator and optional datetime.

        Args:
            db (Session): Database session.
            locator (str): The locator to filter by.
            datetime_filter (Optional[str]): Optional datetime filter.

        Returns:
            List[Tracking]: List of matching tracking entries.
        """
        query = db.query(Tracking).filter(Tracking.locator == locator)
        if datetime_filter:
            query = query.filter(Tracking.tracking_dt == datetime_filter)
        return query.all()

    @staticmethod
    def delete_trackings_for_unindex(db: Session, locator: str, datetime_filter: Optional[str] = None) -> int:
        """
        Delete tracking entries for unindexing.

        Args:
            db (Session): Database session.
            locator (str): The locator to filter by.
            datetime_filter (Optional[str]): Optional datetime filter.

        Returns:
            int: Number of deleted entries.
        """
        query = db.query(Tracking).filter(Tracking.locator == locator)
        if datetime_filter:
            query = query.filter(Tracking.tracking_dt == datetime_filter)
        deleted_count = query.delete(synchronize_session='fetch')
        db.commit()
        return deleted_count
