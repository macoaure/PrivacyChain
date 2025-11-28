"""
Unit tests for CRUD operations.
"""
import pytest
from app.crud.tracking_crud import TrackingCRUD
from app.models.tracking import Tracking
from app.schemas.tracking import TrackingCreate


class TestTrackingCRUD:
    """Test cases for TrackingCRUD."""

    def test_get_tracking_by_id_found(self, test_db_session, sample_tracking_data):
        """Test getting tracking by ID when found."""
        # Create a tracking entry
        tracking = Tracking(**sample_tracking_data)
        test_db_session.add(tracking)
        test_db_session.commit()

        result = TrackingCRUD.get_tracking_by_id(test_db_session, tracking.tracking_id)

        assert result is not None
        assert result.tracking_id == tracking.tracking_id
        assert result.locator == sample_tracking_data["locator"]

    def test_get_tracking_by_id_not_found(self, test_db_session):
        """Test getting tracking by ID when not found."""
        result = TrackingCRUD.get_tracking_by_id(test_db_session, 999)

        assert result is None

    def test_get_tracking_by_transaction_id_found(self, test_db_session, sample_tracking_data):
        """Test getting tracking by transaction ID when found."""
        tracking = Tracking(**sample_tracking_data)
        test_db_session.add(tracking)
        test_db_session.commit()

        result = TrackingCRUD.get_tracking_by_transaction_id(test_db_session, sample_tracking_data["transaction_id"])

        assert result is not None
        assert result.transaction_id == sample_tracking_data["transaction_id"]

    def test_get_tracking_by_transaction_id_not_found(self, test_db_session):
        """Test getting tracking by transaction ID when not found."""
        result = TrackingCRUD.get_tracking_by_transaction_id(test_db_session, "nonexistent")

        assert result is None

    def test_get_trackings(self, test_db_session, sample_tracking_data):
        """Test getting multiple trackings."""
        # Create multiple tracking entries
        for i in range(3):
            data = sample_tracking_data.copy()
            data["transaction_id"] = f"0x{i}"
            tracking = Tracking(**data)
            test_db_session.add(tracking)
        test_db_session.commit()

        results = TrackingCRUD.get_trackings(test_db_session)

        assert len(results) == 3

    def test_get_trackings_with_pagination(self, test_db_session, sample_tracking_data):
        """Test getting trackings with pagination."""
        # Create multiple tracking entries
        for i in range(5):
            data = sample_tracking_data.copy()
            data["transaction_id"] = f"0x{i}"
            tracking = Tracking(**data)
            test_db_session.add(tracking)
        test_db_session.commit()

        results = TrackingCRUD.get_trackings(test_db_session, skip=2, limit=2)

        assert len(results) == 2

    def test_create_tracking(self, test_db_session, sample_tracking_data):
        """Test creating a new tracking entry."""
        tracking_create = TrackingCreate(**sample_tracking_data)

        result = TrackingCRUD.create_tracking(test_db_session, tracking_create)

        assert result.tracking_id is not None
        assert result.canonical_data == sample_tracking_data["canonical_data"]
        assert result.locator == sample_tracking_data["locator"]

        # Verify it was persisted
        persisted = TrackingCRUD.get_tracking_by_id(test_db_session, result.tracking_id)
        assert persisted is not None

    def test_get_trackings_for_unindex_without_datetime(self, test_db_session, sample_tracking_data):
        """Test getting trackings for unindex without datetime filter."""
        # Create multiple trackings with same locator
        for i in range(3):
            data = sample_tracking_data.copy()
            data["transaction_id"] = f"0x{i}"
            tracking = Tracking(**data)
            test_db_session.add(tracking)
        test_db_session.commit()

        results = TrackingCRUD.get_trackings_for_unindex(test_db_session, sample_tracking_data["locator"])

        assert len(results) == 3

    def test_get_trackings_for_unindex_with_datetime(self, test_db_session, sample_tracking_data):
        """Test getting trackings for unindex with datetime filter."""
        # Create trackings with different datetimes
        base_data = sample_tracking_data.copy()
        tracking1 = Tracking(**{**base_data, "tracking_dt": "2023-01-01T00:00:00"})
        tracking2 = Tracking(**{**base_data, "tracking_dt": "2023-01-02T00:00:00", "transaction_id": "0x2"})
        test_db_session.add(tracking1)
        test_db_session.add(tracking2)
        test_db_session.commit()

        results = TrackingCRUD.get_trackings_for_unindex(test_db_session, sample_tracking_data["locator"], "2023-01-01T00:00:00")

        assert len(results) == 1
        assert results[0].tracking_dt == "2023-01-01T00:00:00"

    def test_delete_trackings_for_unindex_without_datetime(self, test_db_session, sample_tracking_data):
        """Test deleting trackings for unindex without datetime filter."""
        # Create trackings
        for i in range(3):
            data = sample_tracking_data.copy()
            data["transaction_id"] = f"0x{i}"
            tracking = Tracking(**data)
            test_db_session.add(tracking)
        test_db_session.commit()

        deleted_count = TrackingCRUD.delete_trackings_for_unindex(test_db_session, sample_tracking_data["locator"])

        assert deleted_count == 3

        # Verify they were deleted
        remaining = TrackingCRUD.get_trackings_for_unindex(test_db_session, sample_tracking_data["locator"])
        assert len(remaining) == 0

    def test_delete_trackings_for_unindex_with_datetime(self, test_db_session, sample_tracking_data):
        """Test deleting trackings for unindex with datetime filter."""
        # Create trackings with different datetimes
        base_data = sample_tracking_data.copy()
        tracking1 = Tracking(**{**base_data, "tracking_dt": "2023-01-01T00:00:00"})
        tracking2 = Tracking(**{**base_data, "tracking_dt": "2023-01-02T00:00:00", "transaction_id": "0x2"})
        test_db_session.add(tracking1)
        test_db_session.add(tracking2)
        test_db_session.commit()

        deleted_count = TrackingCRUD.delete_trackings_for_unindex(test_db_session, sample_tracking_data["locator"], "2023-01-01T00:00:00")

        assert deleted_count == 1

        # Verify only the correct one was deleted
        remaining = TrackingCRUD.get_trackings_for_unindex(test_db_session, sample_tracking_data["locator"])
        assert len(remaining) == 1
        assert remaining[0].tracking_dt == "2023-01-02T00:00:00"
