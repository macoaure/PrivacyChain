"""
Integration tests for proxy re-encryption functionality.

This module tests the integration between proxy encryption services,
database operations, and API endpoints.
"""
import pytest
from unittest.mock import Mock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
import json

from app.database.connection import Base
from app.api.main import app
from app.api.dependencies import get_db
from app.services.proxy_encryption_service import ProxyEncryptionService
from app.crud.proxy_encryption_crud import ProxyKeyCRUD, EncryptedDataCRUD, ShareRecordCRUD


# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_proxy_encryption.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_database():
    """Create test database tables."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    """Create a fresh database session for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sample_keys():
    """Generate sample key pairs for testing."""
    owner_keys = ProxyEncryptionService.generate_key_pair()
    recipient_keys = ProxyEncryptionService.generate_key_pair()
    return {
        "owner": owner_keys,
        "recipient": recipient_keys
    }


class TestProxyEncryptionIntegration:
    """Integration tests for proxy encryption functionality."""

    def test_generate_key_pair_endpoint(self, setup_database):
        """Test key pair generation endpoint."""
        response = client.post("/proxy-encryption/generateKeyPair/")

        assert response.status_code == 200
        data = response.json()
        assert "private_key" in data
        assert "public_key" in data
        assert "BEGIN PRIVATE KEY" in data["private_key"]
        assert "BEGIN PUBLIC KEY" in data["public_key"]

    def test_encrypt_for_owner_endpoint(self, setup_database, sample_keys):
        """Test owner encryption endpoint."""
        payload = {
            "content": "test content for encryption",
            "owner_public_key": sample_keys["owner"]["public_key"],
            "locator": "test-locator-integration"
        }

        response = client.post("/proxy-encryption/encryptForOwner/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "encrypted_content" in data
        assert "encryption_id" in data
        assert data["locator"] == payload["locator"]

    def test_generate_proxy_key_endpoint(self, setup_database, sample_keys):
        """Test proxy key generation endpoint."""
        payload = {
            "owner_private_key": sample_keys["owner"]["private_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "locator": "proxy-key-test",
            "expiration_hours": 24
        }

        response = client.post("/proxy-encryption/generateProxyKey/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "proxy_id" in data
        assert "proxy_key_hash" in data
        assert data["locator"] == payload["locator"]
        assert data["is_revoked"] == False

    @patch('app.services.blockchain_service.BlockchainService')
    def test_generate_proxy_key_with_blockchain(self, mock_blockchain_service, setup_database, sample_keys):
        """Test proxy key generation with blockchain integration."""
        # Mock blockchain service
        mock_blockchain_instance = Mock()
        mock_blockchain_service.return_value = mock_blockchain_instance
        mock_blockchain_instance.generate_proxy_key_on_chain.return_value = "0x1234567890abcdef"

        payload = {
            "owner_private_key": sample_keys["owner"]["private_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "locator": "blockchain-proxy-test",
            "expiration_hours": 48
        }

        response = client.post("/proxy-encryption/generateProxyKey/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "proxy_id" in data
        # Note: blockchain_tx would be in the service response, not the API response

    def test_complete_sharing_workflow_endpoints(self, setup_database, sample_keys):
        """Test complete sharing workflow through API endpoints."""
        locator = "complete-workflow-test"
        content = "sensitive data for complete workflow test"

        # Step 1: Encrypt data for owner
        encrypt_payload = {
            "content": content,
            "owner_public_key": sample_keys["owner"]["public_key"],
            "locator": locator
        }
        encrypt_response = client.post("/proxy-encryption/encryptForOwner/", json=encrypt_payload)
        assert encrypt_response.status_code == 200
        encrypted_data = encrypt_response.json()

        # Step 2: Generate proxy key
        proxy_payload = {
            "owner_private_key": sample_keys["owner"]["private_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "locator": locator,
            "expiration_hours": 24
        }
        proxy_response = client.post("/proxy-encryption/generateProxyKey/", json=proxy_payload)
        assert proxy_response.status_code == 200
        proxy_key = proxy_response.json()

        # Step 3: Re-encrypt data
        re_encrypt_payload = {
            "encrypted_data": encrypted_data,
            "proxy_key": dict(proxy_key, **{
                "proxy_data": {"mock": "data"},  # Simplified for testing
                "salt": "test-salt"
            })
        }
        re_encrypt_response = client.post("/proxy-encryption/reEncryptData/", json=re_encrypt_payload)
        assert re_encrypt_response.status_code == 200
        re_encrypted_data = re_encrypt_response.json()

        # Step 4: Decrypt for recipient
        decrypt_payload = {
            "re_encrypted_data": re_encrypted_data,
            "recipient_private_key": sample_keys["recipient"]["private_key"]
        }
        decrypt_response = client.post("/proxy-encryption/decryptForRecipient/", json=decrypt_payload)
        assert decrypt_response.status_code == 200
        decrypted_result = decrypt_response.json()

        assert decrypted_result["locator"] == locator

    def test_proxy_key_revocation_endpoint(self, setup_database, sample_keys):
        """Test proxy key revocation endpoint."""
        # First generate a proxy key
        proxy_payload = {
            "owner_private_key": sample_keys["owner"]["private_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "locator": "revocation-test",
            "expiration_hours": 24
        }
        proxy_response = client.post("/proxy-encryption/generateProxyKey/", json=proxy_payload)
        assert proxy_response.status_code == 200
        proxy_key = proxy_response.json()

        # Revoke the proxy key
        revoke_payload = {
            "proxy_key": dict(proxy_key, **{
                "proxy_data": {"mock": "data"},
                "salt": "test-salt"
            }),
            "owner_private_key": sample_keys["owner"]["private_key"]
        }
        revoke_response = client.post("/proxy-encryption/revokeProxyKey/", json=revoke_payload)
        assert revoke_response.status_code == 200
        revoke_result = revoke_response.json()

        assert revoke_result["revoked"] == True

    def test_create_secure_share_endpoint(self, setup_database, sample_keys):
        """Test complete secure share creation endpoint."""
        payload = {
            "content": "secure share test content",
            "locator": "secure-share-test",
            "owner_private_key": sample_keys["owner"]["private_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "expiration_hours": 48
        }

        response = client.post("/proxy-encryption/createSecureShare/", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert "share_id" in data
        assert "encrypted_data" in data
        assert "proxy_key" in data
        assert "re_encrypted_data" in data
        assert data["locator"] == payload["locator"]

    def test_proxy_metrics_endpoint(self, setup_database, sample_keys):
        """Test proxy metrics endpoint."""
        # First create some proxy keys
        for i in range(3):
            proxy_payload = {
                "owner_private_key": sample_keys["owner"]["private_key"],
                "recipient_public_key": sample_keys["recipient"]["public_key"],
                "locator": f"metrics-test-{i}",
                "expiration_hours": 24
            }
            client.post("/proxy-encryption/generateProxyKey/", json=proxy_payload)

        # Get metrics
        response = client.get("/proxy-encryption/proxyMetrics/")

        assert response.status_code == 200
        data = response.json()
        assert "total_shares" in data
        assert "active_shares" in data
        assert "revoked_shares" in data
        assert "expired_shares" in data

    def test_database_crud_operations(self, db_session, sample_keys):
        """Test direct CRUD operations with database."""
        # Test proxy key CRUD
        proxy_key_data = {
            "proxy_id": "test-proxy-123",
            "locator": "crud-test",
            "owner_public_key": sample_keys["owner"]["public_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "proxy_key_hash": "test-hash",
            "proxy_data": {"test": "data"},
            "salt": "test-salt",
            "created_at": "2023-01-01T00:00:00",
            "expires_at": "2023-01-02T00:00:00",
            "is_revoked": False
        }

        # Create proxy key
        proxy_key_record = ProxyKeyCRUD.create_proxy_key(db_session, proxy_key_data)
        assert proxy_key_record.proxy_id == "test-proxy-123"

        # Retrieve proxy key
        retrieved_key = ProxyKeyCRUD.get_proxy_key(db_session, "test-proxy-123")
        assert retrieved_key is not None
        assert retrieved_key.locator == "crud-test"

        # Revoke proxy key
        revoked_key = ProxyKeyCRUD.revoke_proxy_key(db_session, "test-proxy-123")
        assert revoked_key.is_revoked == True

    def test_encrypted_data_crud(self, db_session, sample_keys):
        """Test encrypted data CRUD operations."""
        encrypted_data = {
            "encryption_id": "enc-test-123",
            "locator": "enc-crud-test",
            "owner_public_key": sample_keys["owner"]["public_key"],
            "encrypted_content": "encrypted_content_base64",
            "iv": "iv_base64",
            "encrypted_key": "key_base64",
            "key_hash": "key_hash_value"
        }

        # Create encrypted data
        record = EncryptedDataCRUD.create_encrypted_data(db_session, encrypted_data)
        assert record.encryption_id == "enc-test-123"

        # Retrieve by ID
        retrieved = EncryptedDataCRUD.get_encrypted_data(db_session, "enc-test-123")
        assert retrieved is not None
        assert retrieved.locator == "enc-crud-test"

        # Retrieve by locator
        by_locator = EncryptedDataCRUD.get_encrypted_data_by_locator(db_session, "enc-crud-test")
        assert len(by_locator) == 1
        assert by_locator[0].encryption_id == "enc-test-123"

    def test_share_record_crud(self, db_session, sample_keys):
        """Test share record CRUD operations."""
        share_data = {
            "share_id": "share-test-123",
            "locator": "share-crud-test",
            "owner_public_key": sample_keys["owner"]["public_key"],
            "recipient_public_key": sample_keys["recipient"]["public_key"],
            "encryption_id": "enc-123",
            "proxy_id": "proxy-123",
            "re_encryption_id": "re-enc-123"
        }

        # Create share record
        record = ShareRecordCRUD.create_share_record(db_session, share_data)
        assert record.share_id == "share-test-123"

        # Retrieve share record
        retrieved = ShareRecordCRUD.get_share_record(db_session, "share-test-123")
        assert retrieved is not None
        assert retrieved.locator == "share-crud-test"

        # Deactivate share
        deactivated = ShareRecordCRUD.deactivate_share(db_session, "share-test-123")
        assert deactivated.is_active == False

    def test_error_handling_invalid_keys(self, setup_database):
        """Test error handling with invalid keys."""
        # Test with invalid private key
        payload = {
            "owner_private_key": "invalid-private-key",
            "recipient_public_key": "invalid-public-key",
            "locator": "error-test",
            "expiration_hours": 24
        }

        response = client.post("/proxy-encryption/generateProxyKey/", json=payload)
        assert response.status_code == 500

    def test_error_handling_missing_data(self, setup_database, sample_keys):
        """Test error handling with missing data."""
        # Test re-encryption with non-existent proxy key
        re_encrypt_payload = {
            "encrypted_data": {
                "encryption_id": "non-existent",
                "locator": "test",
                "encrypted_content": "content"
            },
            "proxy_key": {
                "proxy_id": "non-existent-proxy",
                "locator": "test",
                "is_revoked": False,
                "expires_at": "2025-01-01T00:00:00"
            }
        }

        response = client.post("/proxy-encryption/reEncryptData/", json=re_encrypt_payload)
        assert response.status_code == 404  # Proxy key not found
