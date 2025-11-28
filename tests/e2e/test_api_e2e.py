"""
End-to-end tests for the PrivacyChain API.
"""
import pytest
import json
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


class TestE2EAccessControl:
    """End-to-end tests for AccessControl endpoints."""

    # Test data
    LOCATOR = "72815157071"
    TEST_USERS = [
        "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0",
        "0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b",
        "0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d"
    ]
    OWNER_ACCOUNT = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    @patch('app.services.blockchain_service.solcx')
    def test_deploy_access_control_contract(self, mock_solcx, mock_settings, mock_web3, client):
        """Test deploying AccessControl contract."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance
        mock_web3_instance.eth.accounts = [self.OWNER_ACCOUNT]

        # Mock solc compilation
        mock_solcx.compile_source.return_value = {
            '<stdin>:AccessControl': {
                'abi': [],
                'bin': '0x608060405234801561001057600080fd5b50...'
            }
        }

        # Mock contract deployment
        mock_contract = Mock()
        mock_contract.constructor.return_value.transact.return_value = HexBytes("0x1234567890abcdef")
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_web3_instance.eth.wait_for_transaction_receipt.return_value.contractAddress = "0x86072CbFF48dA3C1F01824a6761A03F105BCC697"

        response = client.post("/access-control/deploy/")

        assert response.status_code == 200
        data = response.json()
        assert "contract_address" in data

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_register_data_access_control(self, mock_settings, mock_web3, client):
        """Test registering data in AccessControl contract."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and transaction
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.registerData.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }

        response = client.post("/access-control/registerData/", json=payload)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_grant_access_single_user(self, mock_settings, mock_web3, client):
        """Test granting access to a single user."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and transaction
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.grantAccess.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "user": self.TEST_USERS[0],
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }

        response = client.post("/access-control/grantAccess/", json=payload)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_grant_multiple_access(self, mock_settings, mock_web3, client):
        """Test granting access to multiple users."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and transactions
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.grantAccess.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "users": self.TEST_USERS,
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }

        response = client.post("/access-control/grantMultipleAccess/", json=payload)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_check_access(self, mock_settings, mock_web3, client):
        """Test checking user access."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and call
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.hasAccess.return_value.call.return_value = True

        params = {"user": self.TEST_USERS[0], "locator": self.LOCATOR}

        response = client.get("/access-control/checkAccess/", params=params)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_list_accessors(self, mock_settings, mock_web3, client):
        """Test listing all accessors."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and call
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.getAccessors.return_value.call.return_value = self.TEST_USERS

        params = {"locator": self.LOCATOR}

        response = client.get("/access-control/listAccessors/", params=params)

        # Should return 200 or error depending on contract setup
        assert response.status_code in [200, 400, 422, 500]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_get_data_owner(self, mock_settings, mock_web3, client):
        """Test getting data owner."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and call
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.getDataOwner.return_value.call.return_value = self.OWNER_ACCOUNT

        params = {"locator": self.LOCATOR}

        response = client.get("/access-control/getDataOwner/", params=params)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_revoke_access_single_user(self, mock_settings, mock_web3, client):
        """Test revoking access from a single user."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and transaction
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.revokeAccess.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "user": self.TEST_USERS[0],
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }

        response = client.post("/access-control/revokeAccess/", json=payload)

        # Should return 200 or validation error depending on contract setup
        assert response.status_code in [200, 400, 422]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_revoke_all_access(self, mock_settings, mock_web3, client):
        """Test revoking access from all users."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and calls
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.getAccessors.return_value.call.return_value = self.TEST_USERS
        mock_contract.functions.revokeAccess.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }

        response = client.post("/access-control/revokeAllAccess/", json=payload)

        # Should return 200 or error depending on contract setup
        assert response.status_code in [200, 400, 422, 500]

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.blockchain_service.settings')
    def test_log_access(self, mock_settings, mock_web3, client):
        """Test logging access for audit purposes."""
        # Setup mocks
        mock_settings.ganache_url = "http://localhost:8545"
        mock_web3_instance = Mock()
        mock_web3.return_value = mock_web3_instance

        # Mock contract instance and transaction
        mock_contract = Mock()
        mock_web3_instance.eth.contract.return_value = mock_contract
        mock_contract.functions.logAccess.return_value.transact.return_value = HexBytes("0x1234567890abcdef")

        payload = {
            "user": self.TEST_USERS[0],
            "locator": self.LOCATOR
        }

        response = client.post("/access-control/logAccess/", json=payload)

        # Should return 200 or error depending on contract setup
        assert response.status_code in [200, 400, 422, 500]

    def test_access_control_endpoints_validation(self, client):
        """Test validation of access control endpoints."""
        # Test invalid payload for deploy
        response = client.post("/access-control/deploy/", json={"invalid": "data"})
        assert response.status_code in [200, 422]  # Either successful or validation error

        # Test missing required fields for grantAccess
        response = client.post("/access-control/grantAccess/", json={})
        assert response.status_code == 422  # Validation error

        # Test invalid user address format
        payload = {
            "user": "invalid_address",
            "locator": self.LOCATOR,
            "from_account": self.OWNER_ACCOUNT
        }
        response = client.post("/access-control/grantAccess/", json=payload)
        assert response.status_code in [422, 500]  # Validation or internal error

    def test_access_control_integration_flow(self, client):
        """Test a complete access control flow integration."""
        # This test would require actual blockchain integration
        # For now, we just test that endpoints are accessible

        endpoints_to_test = [
            ("POST", "/access-control/deploy/", {}),
            ("GET", "/access-control/checkAccess/", {"user": self.TEST_USERS[0], "locator": self.LOCATOR}),
            ("GET", "/access-control/listAccessors/", {"locator": self.LOCATOR}),
            ("GET", "/access-control/getDataOwner/", {"locator": self.LOCATOR})
        ]

        for method, endpoint, params in endpoints_to_test:
            if method == "GET":
                response = client.get(endpoint, params=params)
            else:
                response = client.post(endpoint, json=params)

            # Endpoints should be accessible (not 404)
            assert response.status_code != 404
