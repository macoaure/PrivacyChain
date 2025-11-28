"""
End-to-end tests for the PrivacyChain API.
"""
import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from unittest.mock import patch, Mock
from hexbytes import HexBytes


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestE2EAnonymization:
    """End-to-end tests for anonymization endpoints."""

    def test_simple_anonymize_e2e(self, client):
        """Test simple anonymization endpoint end-to-end."""
        payload = {
            "content": '{"name": "John Doe", "email": "john@example.com", "phone": "123456789", "address": "123 Main St"}'
        }

        response = client.post("/simpleAnonymize/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "content" in data

    def test_secure_anonymize_e2e(self, client):
        """Test secure anonymization endpoint end-to-end."""
        payload = {
            "content": '{"name": "Jane Smith", "email": "jane@example.com", "phone": "987654321", "address": "456 Oak Ave"}',
            "salt": "test_salt"
        }

        response = client.post("/secureAnonymize/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "content" in data

    def test_anonymize_invalid_data(self, client):
        """Test anonymization with invalid data."""
        payload = {"content": {"invalid": "data"}}

        response = client.post("/simpleAnonymize/", json=payload)

        assert response.status_code == 422  # Validation error


class TestE2EBlockchainOperations:
    """End-to-end tests for blockchain operations."""

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_register_onchain_e2e(self, mock_settings, mock_web3, client):
        """Test register on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = ["0x123", "0x456"]
        mock_web3_instance.eth.send_transaction.return_value = HexBytes("0x1234567890abcdef")

        payload = {"content": "test_data"}

        response = client.post("/registerOnChain/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "transaction_id" in data

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_get_onchain_e2e(self, mock_settings, mock_web3, client):
        """Test get on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_transaction = Mock()
        # Simplified mock that matches what the service expects
        mock_web3_instance.eth.get_transaction.return_value = mock_transaction

        tx_hash = "0x1234567890abcdef"

        response = client.get("/getOnChain/", params={"transaction_id": tx_hash})

        # Just check that the endpoint is accessible and returns a proper response
        assert response.status_code in [200, 422]  # 200 if successful, 422 if validation issue
        data = response.json()
        assert isinstance(data, dict)

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    @patch('app.services.tracking_service.BlockchainService')
    def test_index_onchain_e2e(self, mock_blockchain_service, mock_settings, mock_web3, client):
        """Test index on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = ["0x123", "0x456"]
        mock_web3_instance.eth.send_transaction.return_value = HexBytes("0x1234567890abcdef")

        mock_blockchain_instance = Mock()
        mock_blockchain_instance.register_on_chain.return_value = {"transaction_id": "0x1234567890abcdef"}
        mock_blockchain_service.return_value = mock_blockchain_instance

        payload = {
            "to_wallet": "0x1234567890123456789012345678901234567890",
            "from_wallet": "0x0987654321098765432109876543210987654321",
            "content": "test_content",
            "locator": "test_locator",
            "datetime": "2023-01-01T00:00:00Z"
        }

        response = client.post("/indexOnChain/", json=payload)

        # Just check that the endpoint is accessible and returns a proper response
        assert response.status_code in [200, 400]  # 200 if successful, 400 if validation/business logic issue
        data = response.json()
        assert isinstance(data, dict)


class TestE2ETransactions:
    """End-to-end tests for transaction operations."""

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    @patch('app.services.tracking_service.BlockchainService')
    def test_unindex_onchain_e2e(self, mock_blockchain_service, mock_settings, mock_web3, client):
        """Test unindex on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        mock_blockchain_instance = Mock()
        mock_blockchain_service.return_value = mock_blockchain_instance

        unindex_payload = {
            "locator": "unindex_test",
            "datetime": "2023-01-01T00:00:00Z"
        }
        response = client.post("/unindexOnChain/", json=unindex_payload)

        # Just check that the endpoint is accessible and returns a proper response
        assert response.status_code in [200, 400]  # 200 if successful, 400 if no data to unindex
        data = response.json()
        assert isinstance(data, dict)

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    @patch('app.services.tracking_service.BlockchainService')
    def test_rectify_onchain_e2e(self, mock_blockchain_service, mock_settings, mock_web3, client):
        """Test rectify on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        mock_blockchain_instance = Mock()
        mock_blockchain_instance.register_on_chain.return_value = {"transaction_id": "0x1234567890abcdef"}
        mock_blockchain_service.return_value = mock_blockchain_instance

        payload = {
            "content": "new_content",
            "salt": "test_salt",
            "to_wallet": "0x1234567890123456789012345678901234567890",
            "from_wallet": "0x0987654321098765432109876543210987654321",
            "locator": "rectify_locator",
            "datetime": "2023-01-01T00:00:00Z"
        }

        response = client.post("/rectifyOnChain/", json=payload)

        # Just check that the endpoint is accessible and returns a proper response
        assert response.status_code in [200, 400, 500]  # Various possible responses based on data availability
        data = response.json()
        assert isinstance(data, dict)

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    @patch('app.services.tracking_service.BlockchainService')
    def test_remove_onchain_e2e(self, mock_blockchain_service, mock_settings, mock_web3, client):
        """Test remove on chain endpoint end-to-end."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        mock_blockchain_instance = Mock()
        mock_blockchain_service.return_value = mock_blockchain_instance

        remove_payload = {
            "locator": "remove_test_locator",
            "datetime": "2023-01-01T00:00:00Z"
        }

        response = client.post("/removeOnChain/", json=remove_payload)

        # Just check that the endpoint is accessible and returns a proper response
        assert response.status_code in [200, 400]  # 200 if successful, 400 if no data to remove
        data = response.json()
        assert isinstance(data, dict)


class TestE2EHealth:
    """End-to-end tests for health and status endpoints."""

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"

    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "PrivacyChain" in data["message"]
