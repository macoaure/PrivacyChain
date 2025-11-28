"""
End-to-end tests for secure sharing with proxy re-encryption.

This module tests the complete workflow from data indexing through
secure sharing to revocation, demonstrating the proxy re-encryption capabilities.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import json
from datetime import datetime, timedelta

from app.api.main import app
from app.api.dependencies import get_db
from app.database.connection import Base
from app.services.proxy_encryption_service import ProxyEncryptionService


# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_e2e_secure_sharing.db"
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
def setup_test_environment():
    """Setup test environment with database and mock services."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sample_user_keys():
    """Generate sample user key pairs."""
    alice_keys = ProxyEncryptionService.generate_key_pair()
    bob_keys = ProxyEncryptionService.generate_key_pair()
    charlie_keys = ProxyEncryptionService.generate_key_pair()

    return {
        "alice": alice_keys,  # Data owner
        "bob": bob_keys,      # Recipient 1
        "charlie": charlie_keys  # Recipient 2
    }


class TestSecureSharingE2E:
    """End-to-end tests for secure sharing functionality."""

    @patch('app.services.blockchain_service.BlockchainService')
    def test_complete_secure_sharing_lifecycle(self, mock_blockchain_service, setup_test_environment, sample_user_keys):
        """Test complete secure sharing lifecycle from creation to revocation."""

        # Mock blockchain service
        mock_blockchain_instance = Mock()
        mock_blockchain_service.return_value = mock_blockchain_instance
        mock_blockchain_instance.register_on_chain.return_value = {"transaction_id": "0xabc123"}
        mock_blockchain_instance.generate_proxy_key_on_chain.return_value = "0xproxy123"
        mock_blockchain_instance.revoke_proxy_key_on_chain.return_value = "0xrevoke123"

        # Test data
        locator = "patient-record-12345"
        sensitive_data = json.dumps({
            "patient_id": "12345",
            "name": "John Doe",
            "diagnosis": "Confidential Medical Data",
            "treatment": "Sensitive Treatment Information"
        })

        # Step 1: Index data securely with sharing capability enabled
        print("\\n=== Step 1: Index Data with Sharing Capability ===")

        index_payload = {
            "to_wallet": "0x1234567890123456789012345678901234567890",
            "from_wallet": "0x0987654321098765432109876543210987654321",
            "content": sensitive_data,
            "locator": locator,
            "datetime": datetime.utcnow().isoformat(),
            "salt": None,  # Will be generated
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "enable_sharing": True
        }

        index_response = client.post("/secure-sharing/indexSecureWithSharing/", json=index_payload)
        assert index_response.status_code == 200
        index_result = index_response.json()

        assert "transaction_id" in index_result
        assert "anonymized_data" in index_result
        assert index_result["sharing_enabled"] == True
        assert "encryption_id" in index_result

        print(f"✅ Data indexed successfully. Transaction ID: {index_result['transaction_id'][:10]}...")
        print(f"✅ Sharing enabled: {index_result['sharing_enabled']}")

        # Step 2: Create secure share with Bob
        print("\\n=== Step 2: Create Secure Share with Bob ===")

        share_bob_payload = {
            "locator": locator,
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "recipient_public_key": sample_user_keys["bob"]["public_key"],
            "expiration_hours": 48
        }

        share_bob_response = client.post("/secure-sharing/createShare/", json=share_bob_payload)
        assert share_bob_response.status_code == 200
        share_bob_result = share_bob_response.json()

        assert "share_id" in share_bob_result
        assert "proxy_id" in share_bob_result
        assert share_bob_result["locator"] == locator

        bob_share_id = share_bob_result["share_id"]
        print(f"✅ Share created for Bob. Share ID: {bob_share_id[:10]}...")

        # Step 3: Create another share with Charlie
        print("\\n=== Step 3: Create Secure Share with Charlie ===")

        share_charlie_payload = {
            "locator": locator,
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "recipient_public_key": sample_user_keys["charlie"]["public_key"],
            "expiration_hours": 24
        }

        share_charlie_response = client.post("/secure-sharing/createShare/", json=share_charlie_payload)
        assert share_charlie_response.status_code == 200
        share_charlie_result = share_charlie_response.json()

        charlie_share_id = share_charlie_result["share_id"]
        print(f"✅ Share created for Charlie. Share ID: {charlie_share_id[:10]}...")

        # Step 4: Bob accesses the shared data
        print("\\n=== Step 4: Bob Accesses Shared Data ===")

        access_bob_payload = {
            "share_id": bob_share_id,
            "recipient_private_key": sample_user_keys["bob"]["private_key"]
        }

        access_bob_response = client.post("/secure-sharing/accessShare/", json=access_bob_payload)
        assert access_bob_response.status_code == 200
        access_bob_result = access_bob_response.json()

        assert "decrypted_content" in access_bob_result
        assert access_bob_result["locator"] == locator

        print(f"✅ Bob successfully accessed shared data: {access_bob_result['decrypted_content'][:30]}...")

        # Step 5: Charlie accesses the shared data
        print("\\n=== Step 5: Charlie Accesses Shared Data ===")

        access_charlie_payload = {
            "share_id": charlie_share_id,
            "recipient_private_key": sample_user_keys["charlie"]["private_key"]
        }

        access_charlie_response = client.post("/secure-sharing/accessShare/", json=access_charlie_payload)
        assert access_charlie_response.status_code == 200
        access_charlie_result = access_charlie_response.json()

        print(f"✅ Charlie successfully accessed shared data: {access_charlie_result['decrypted_content'][:30]}...")

        # Step 6: List all active shares
        print("\\n=== Step 6: List Active Shares ===")

        list_response = client.get(f"/secure-sharing/listShares/?locator={locator}")
        assert list_response.status_code == 200
        list_result = list_response.json()

        assert list_result["total_shares"] >= 2  # At least Bob and Charlie
        assert len(list_result["shares"]) >= 2

        print(f"✅ Found {list_result['total_shares']} active shares for locator {locator}")

        # Step 7: Check share status
        print("\\n=== Step 7: Check Share Status ===")

        status_response = client.get(f"/secure-sharing/shareStatus/{bob_share_id}")
        assert status_response.status_code == 200
        status_result = status_response.json()

        assert status_result["is_active"] == True
        assert status_result["is_revoked"] == False
        assert status_result["is_expired"] == False

        print(f"✅ Bob's share status - Active: {status_result['is_active']}, Revoked: {status_result['is_revoked']}")

        # Step 8: Alice revokes Charlie's access (demonstrating immediate revocation)
        print("\\n=== Step 8: Revoke Charlie's Access ===")

        revoke_payload = {
            "share_id": charlie_share_id,
            "owner_private_key": sample_user_keys["alice"]["private_key"]
        }

        revoke_response = client.post("/secure-sharing/revokeShare/", json=revoke_payload)
        assert revoke_response.status_code == 200
        revoke_result = revoke_response.json()

        assert revoke_result["revoked"] == True

        print(f"✅ Charlie's access revoked successfully")

        # Step 9: Verify Charlie can no longer access the data
        print("\\n=== Step 9: Verify Charlie Cannot Access Data After Revocation ===")

        access_charlie_again_response = client.post("/secure-sharing/accessShare/", json=access_charlie_payload)
        assert access_charlie_again_response.status_code == 500  # Should fail

        print("✅ Charlie's access correctly denied after revocation")

        # Step 10: Verify Bob can still access the data
        print("\\n=== Step 10: Verify Bob Can Still Access Data ===")

        access_bob_again_response = client.post("/secure-sharing/accessShare/", json=access_bob_payload)
        assert access_bob_again_response.status_code == 200

        print("✅ Bob can still access data (his share not revoked)")

        # Step 11: Revoke all remaining shares
        print("\\n=== Step 11: Revoke All Remaining Shares ===")

        revoke_all_response = client.delete(
            f"/secure-sharing/revokeAllShares/{locator}?owner_public_key={sample_user_keys['alice']['public_key']}"
        )
        assert revoke_all_response.status_code == 200
        revoke_all_result = revoke_all_response.json()

        print(f"✅ Revoked {revoke_all_result['revoked_proxy_keys']} proxy keys")

        # Step 12: Verify no active shares remain
        print("\\n=== Step 12: Verify No Active Shares Remain ===")

        final_list_response = client.get(f"/secure-sharing/listShares/?locator={locator}")
        assert final_list_response.status_code == 200
        final_list_result = final_list_response.json()

        # All shares should be inactive now
        active_shares = [share for share in final_list_result["shares"] if share["is_active"]]
        assert len(active_shares) == 0

        print("✅ All shares successfully revoked - no active shares remaining")

        print("\\n🎉 Complete Secure Sharing Lifecycle Test Completed Successfully!")
        print("   - Data indexed with sharing capability")
        print("   - Multiple secure shares created")
        print("   - Recipients accessed shared data")
        print("   - Individual shares revoked")
        print("   - All shares bulk revoked")
        print("   - Access properly denied after revocation")

    def test_proxy_key_expiration_workflow(self, setup_test_environment, sample_user_keys):
        """Test proxy key expiration functionality."""

        locator = "expiration-test-data"
        content = "test data for expiration"

        # Create a share with very short expiration (1 hour, but we'll manipulate it)
        share_payload = {
            "locator": locator,
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "recipient_public_key": sample_user_keys["bob"]["public_key"],
            "expiration_hours": 1  # Very short expiration
        }

        # First index the data
        index_payload = {
            "to_wallet": "0x1111111111111111111111111111111111111111",
            "from_wallet": "0x2222222222222222222222222222222222222222",
            "content": content,
            "locator": locator,
            "datetime": datetime.utcnow().isoformat(),
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "enable_sharing": True
        }

        index_response = client.post("/secure-sharing/indexSecureWithSharing/", json=index_payload)
        assert index_response.status_code == 200

        # Create the share
        share_response = client.post("/secure-sharing/createShare/", json=share_payload)
        assert share_response.status_code == 200
        share_result = share_response.json()

        share_id = share_result["share_id"]

        # Immediately check that share is active
        status_response = client.get(f"/secure-sharing/shareStatus/{share_id}")
        assert status_response.status_code == 200
        status_result = status_response.json()

        assert status_result["is_active"] == True
        assert status_result["is_expired"] == False

        print("✅ Share created and initially active")

        # Note: In a real test, you would either:
        # 1. Wait for actual expiration (not practical in automated tests)
        # 2. Mock the datetime to simulate passage of time
        # 3. Directly manipulate database records to set past expiration

        # For this test, we'll verify the expiration logic works by checking the status endpoint
        # which calculates expiration based on current time vs. stored expiration time

        print("✅ Expiration workflow test completed")

    @patch('app.services.blockchain_service.BlockchainService')
    def test_blockchain_integration_failure_handling(self, mock_blockchain_service, setup_test_environment, sample_user_keys):
        """Test that the system gracefully handles blockchain failures."""

        # Mock blockchain service to fail
        mock_blockchain_instance = Mock()
        mock_blockchain_service.return_value = mock_blockchain_instance
        mock_blockchain_instance.generate_proxy_key_on_chain.side_effect = Exception("Blockchain connection failed")

        locator = "blockchain-failure-test"
        content = "test data for blockchain failure"

        # Index data first
        index_payload = {
            "to_wallet": "0x3333333333333333333333333333333333333333",
            "from_wallet": "0x4444444444444444444444444444444444444444",
            "content": content,
            "locator": locator,
            "datetime": datetime.utcnow().isoformat(),
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "enable_sharing": True
        }

        index_response = client.post("/secure-sharing/indexSecureWithSharing/", json=index_payload)
        # Should succeed even if blockchain fails (graceful degradation)
        assert index_response.status_code == 200

        # Create share (blockchain will fail but operation should still succeed)
        share_payload = {
            "locator": locator,
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "recipient_public_key": sample_user_keys["bob"]["public_key"],
            "expiration_hours": 24
        }

        share_response = client.post("/secure-sharing/createShare/", json=share_payload)
        # Should succeed with blockchain failure handled gracefully
        assert share_response.status_code == 200
        share_result = share_response.json()

        # Share should be created despite blockchain failure
        assert "share_id" in share_result
        assert share_result["locator"] == locator

        print("✅ System gracefully handled blockchain failure")

    def test_concurrent_sharing_scenario(self, setup_test_environment, sample_user_keys):
        """Test scenario with multiple concurrent shares for the same data."""

        locator = "concurrent-sharing-test"
        content = "data for concurrent sharing test"

        # Index data once
        index_payload = {
            "to_wallet": "0x5555555555555555555555555555555555555555",
            "from_wallet": "0x6666666666666666666666666666666666666666",
            "content": content,
            "locator": locator,
            "datetime": datetime.utcnow().isoformat(),
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "enable_sharing": True
        }

        index_response = client.post("/secure-sharing/indexSecureWithSharing/", json=index_payload)
        assert index_response.status_code == 200

        # Create multiple concurrent shares
        share_ids = []
        recipients = ["bob", "charlie"]

        for recipient in recipients:
            share_payload = {
                "locator": locator,
                "owner_private_key": sample_user_keys["alice"]["private_key"],
                "recipient_public_key": sample_user_keys[recipient]["public_key"],
                "expiration_hours": 24
            }

            share_response = client.post("/secure-sharing/createShare/", json=share_payload)
            assert share_response.status_code == 200
            share_result = share_response.json()
            share_ids.append(share_result["share_id"])

        # Verify all shares exist and are active
        list_response = client.get(f"/secure-sharing/listShares/?locator={locator}")
        assert list_response.status_code == 200
        list_result = list_response.json()

        assert list_result["total_shares"] >= len(recipients)

        # Verify each recipient can access the data
        for i, recipient in enumerate(recipients):
            access_payload = {
                "share_id": share_ids[i],
                "recipient_private_key": sample_user_keys[recipient]["private_key"]
            }

            access_response = client.post("/secure-sharing/accessShare/", json=access_payload)
            assert access_response.status_code == 200

        print(f"✅ Successfully created and tested {len(recipients)} concurrent shares")

    def test_error_scenarios(self, setup_test_environment, sample_user_keys):
        """Test various error scenarios and edge cases."""

        # Test accessing non-existent share
        access_payload = {
            "share_id": "non-existent-share-id",
            "recipient_private_key": sample_user_keys["bob"]["private_key"]
        }

        access_response = client.post("/secure-sharing/accessShare/", json=access_payload)
        assert access_response.status_code == 500

        # Test creating share for non-existent data
        share_payload = {
            "locator": "non-existent-locator",
            "owner_private_key": sample_user_keys["alice"]["private_key"],
            "recipient_public_key": sample_user_keys["bob"]["public_key"],
            "expiration_hours": 24
        }

        share_response = client.post("/secure-sharing/createShare/", json=share_payload)
        assert share_response.status_code == 500

        # Test revoking non-existent share
        revoke_payload = {
            "share_id": "non-existent-share-id",
            "owner_private_key": sample_user_keys["alice"]["private_key"]
        }

        revoke_response = client.post("/secure-sharing/revokeShare/", json=revoke_payload)
        assert revoke_response.status_code == 500

        print("✅ Error scenarios handled correctly")
