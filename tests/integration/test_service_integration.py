"""
Integration tests for service interactions.
"""
import pytest
from unittest.mock import Mock, patch
from app.services.tracking_service import TrackingService
from app.services.anonymization_service import AnonymizationService
from app.services.blockchain_service import BlockchainService
from app.schemas.entity import Entity
from app.crud.tracking_crud import TrackingCRUD


class TestServiceIntegration:
    """Test cases for service interactions."""

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_tracking_service_index_on_chain_integration(self, mock_settings, mock_web3, test_db_session):
        """Test TrackingService.index_on_chain integrates AnonymizationService and BlockchainService."""
        # Setup mocks
        mock_settings.GANACHE_URL = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = ["0x123", "0x456"]
        mock_transaction = Mock()
        mock_transaction.hex.return_value = "0xabcdef"
        mock_web3_instance.eth.send_transaction.return_value = mock_transaction

        # Create services
        tracking_service = TrackingService()

        # Test data
        content = '{"name":"John Doe","email":"john@example.com","phone":"123456789","address":"123 Main St"}'

        # Execute
        result = tracking_service.index_on_chain(test_db_session, content, "test_locator")

        # Verify integration
        assert "tracking_id" in result
        assert "transaction_id" in result

        # Verify data was persisted
        persisted = TrackingCRUD.get_tracking_by_transaction_id(test_db_session, result["transaction_id"])
        assert persisted is not None
        assert persisted.locator == "test_locator"
        assert persisted.canonical_data == content

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_tracking_service_unindex_on_chain_integration(self, mock_settings, mock_web3, test_db_session):
        """Test TrackingService.unindex_on_chain integrates with CRUD operations."""
        # Setup mocks
        mock_settings.GANACHE_URL = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = ["0x123", "0x456"]
        mock_transaction = Mock()
        mock_transaction.hex.return_value = "0xabcdef"
        mock_web3_instance.eth.send_transaction.return_value = mock_transaction

        # Create services
        tracking_service = TrackingService()

        # First, create some tracking data
        content = '{"name":"Jane Doe","email":"jane@example.com","phone":"987654321","address":"456 Oak St"}'

        # Index first
        tracking_service.index_on_chain(test_db_session, content, "unindex_locator")

        # Now unindex
        unindex_result = tracking_service.unindex_on_chain(test_db_session, "unindex_locator")

        # Verify unindex worked
        assert "deleted_count" in unindex_result
        assert unindex_result["deleted_count"] > 0

        # Verify data was removed
        remaining = TrackingCRUD.get_trackings_for_unindex(test_db_session, "unindex_locator")
        assert len(remaining) == 0

    def test_anonymization_service_with_tracking_service(self, test_db_session):
        """Test AnonymizationService integration within TrackingService context."""
        # Create services
        anonymization_service = AnonymizationService()

        # Test data
        content = '{"name":"Test User","email":"test@example.com","phone":"555-1234","address":"789 Pine St"}'

        # Test simple anonymization
        simple_result = anonymization_service.simple_anonymize(content)
        assert simple_result is not None
        assert isinstance(simple_result, dict)
        assert "content" in simple_result

        # Test secure anonymization
        secure_result = anonymization_service.secure_anonymize(content)
        assert secure_result is not None
        assert isinstance(secure_result, dict)
        assert "content" in secure_result

        # Verify they produce different results
        assert simple_result["content"] != secure_result["content"]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_blockchain_service_with_tracking_service(self, mock_settings, mock_web3, test_db_session):
        """Test BlockchainService integration within TrackingService context."""
        # Setup mocks
        mock_settings.GANACHE_URL = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = ["0x123", "0x456"]
        mock_transaction = Mock()
        mock_transaction.hex.return_value = "0xabcdef"
        mock_web3_instance.eth.send_transaction.return_value = mock_transaction

        # Create services
        blockchain_service = BlockchainService()

        # Test data
        test_data = "test_data_string"

        # Test register on chain
        tx_result = blockchain_service.register_on_chain(test_data)
        assert tx_result is not None
        assert "transaction_id" in tx_result
        assert tx_result["transaction_id"] == "0xabcdef"
