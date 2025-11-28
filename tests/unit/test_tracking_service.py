"""
Unit tests for the TrackingService.
"""
import pytest
from unittest.mock import Mock, patch
from app.services.tracking_service import TrackingService
from app.schemas.tracking import TrackingCreate


class TestTrackingService:
    """Test cases for TrackingService."""

    @patch('app.services.tracking_service.BlockchainService')
    def test_init(self, mock_blockchain_service):
        """Test TrackingService initialization."""
        service = TrackingService()
        assert isinstance(service.blockchain_service, Mock)

    @patch('app.services.tracking_service.BlockchainService')
    @patch('app.services.anonymization_service.AnonymizationService.simple_anonymize')
    def test_index_on_chain_success(self, mock_simple_anonymize, mock_blockchain_service_class, test_db_session):
        """Test successful indexing on chain."""
        # Setup mocks
        mock_blockchain_service = Mock()
        mock_blockchain_service_class.return_value = mock_blockchain_service
        mock_blockchain_service.register_on_chain.return_value = {"transaction_id": "0x123"}
        mock_simple_anonymize.return_value = {"content": "hashed_data"}

        # Mock CRUD operations
        with patch('app.services.tracking_service.TrackingCRUD') as mock_crud:
            mock_crud.get_tracking_by_transaction_id.return_value = None
            mock_crud.create_tracking.return_value = Mock(tracking_id=1, transaction_id="0x123")

            service = TrackingService()
            result = service.index_on_chain(test_db_session, "test_content", "test_locator")

            assert "tracking_id" in result
            mock_simple_anonymize.assert_called_once_with("test_content", "SHA256")
            mock_blockchain_service.register_on_chain.assert_called_once_with("hashed_data")
            mock_crud.create_tracking.assert_called_once()

    @patch('app.services.tracking_service.BlockchainService')
    @patch('app.services.anonymization_service.AnonymizationService.simple_anonymize')
    def test_index_on_chain_duplicate_transaction(self, mock_simple_anonymize, mock_blockchain_service_class, test_db_session):
        """Test indexing with duplicate transaction ID."""
        mock_blockchain_service = Mock()
        mock_blockchain_service_class.return_value = mock_blockchain_service
        mock_blockchain_service.register_on_chain.return_value = {"transaction_id": "0x123"}
        mock_simple_anonymize.return_value = {"content": "hashed_data"}

        with patch('app.services.tracking_service.TrackingCRUD') as mock_crud:
            mock_crud.get_tracking_by_transaction_id.return_value = Mock()  # Existing tracking

            service = TrackingService()

            with pytest.raises(Exception, match="Transaction already registered"):
                service.index_on_chain(test_db_session, "test_content", "test_locator")

    @patch('app.services.tracking_service.BlockchainService')
    @patch('app.services.anonymization_service.AnonymizationService.secure_anonymize')
    def test_index_secure_on_chain_success(self, mock_secure_anonymize, mock_blockchain_service_class, test_db_session):
        """Test successful secure indexing on chain."""
        mock_blockchain_service = Mock()
        mock_blockchain_service_class.return_value = mock_blockchain_service
        mock_blockchain_service.register_on_chain.return_value = {"transaction_id": "0x123"}
        mock_secure_anonymize.return_value = {"content": "secure_hashed_data"}

        with patch('app.services.tracking_service.TrackingCRUD') as mock_crud:
            mock_crud.get_tracking_by_transaction_id.return_value = None
            mock_crud.create_tracking.return_value = Mock(tracking_id=1, transaction_id="0x123")

            service = TrackingService()
            result = service.index_secure_on_chain(test_db_session, "test_content", "test_locator", "test_salt")

            assert "tracking_id" in result
            mock_secure_anonymize.assert_called_once_with("test_content", "test_salt", "SHA256")
            mock_blockchain_service.register_on_chain.assert_called_once_with("secure_hashed_data")

    def test_unindex_on_chain_success(self, test_db_session):
        """Test successful unindexing."""
        with patch('app.services.tracking_service.TrackingCRUD') as mock_crud:
            mock_crud.get_trackings_for_unindex.return_value = [Mock(), Mock()]  # Two trackings
            mock_crud.delete_trackings_for_unindex.return_value = 2

            service = TrackingService()
            result = service.unindex_on_chain(test_db_session, "test_locator")

            assert result == {"deleted_count": 2}
            mock_crud.get_trackings_for_unindex.assert_called_once_with(test_db_session, "test_locator", None)
            mock_crud.delete_trackings_for_unindex.assert_called_once_with(test_db_session, "test_locator", None)

    def test_unindex_on_chain_no_entries(self, test_db_session):
        """Test unindexing with no entries."""
        with patch('app.services.tracking_service.TrackingCRUD') as mock_crud:
            mock_crud.get_trackings_for_unindex.return_value = []

            service = TrackingService()

            with pytest.raises(Exception, match="Nothing to unindex"):
                service.unindex_on_chain(test_db_session, "test_locator")

    @patch('app.services.tracking_service.TrackingService.unindex_on_chain')
    @patch('app.services.tracking_service.TrackingService.index_secure_on_chain')
    def test_rectify_on_chain_success(self, mock_index_secure, mock_unindex, test_db_session):
        """Test successful rectification."""
        mock_index_secure.return_value = {"tracking_id": 2, "transaction_id": "0x456"}

        service = TrackingService()
        result = service.rectify_on_chain(test_db_session, "new_content", "new_salt", "test_locator", "2023-01-01")

        assert result == {"tracking_id": 2, "transaction_id": "0x456"}
        mock_unindex.assert_called_once_with(test_db_session, "test_locator", "")
        mock_index_secure.assert_called_once_with(test_db_session, "new_content", "test_locator", "new_salt", "SHA256")

    def test_remove_on_chain(self, test_db_session):
        """Test remove on chain (alias for unindex)."""
        with patch.object(TrackingService, 'unindex_on_chain') as mock_unindex:
            mock_unindex.return_value = {"deleted_count": 1}

            service = TrackingService()
            result = service.remove_on_chain(test_db_session, "test_locator", "2023-01-01")

            assert result == {"deleted_count": 1}
            mock_unindex.assert_called_once_with(test_db_session, "test_locator", "2023-01-01")
