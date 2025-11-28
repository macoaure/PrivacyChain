"""
Unit tests for proxy re-encryption service.

This module tests the proxy re-encryption functionality including key generation,
encryption, re-encryption, decryption, and key revocation.
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import json

from app.services.proxy_encryption_service import ProxyEncryptionService


class TestProxyEncryptionService:
    """Test cases for ProxyEncryptionService."""

    def test_generate_key_pair(self):
        """Test ECC key pair generation."""
        result = ProxyEncryptionService.generate_key_pair()

        assert "private_key" in result
        assert "public_key" in result
        assert isinstance(result["private_key"], str)
        assert isinstance(result["public_key"], str)
        assert "BEGIN PRIVATE KEY" in result["private_key"]
        assert "BEGIN PUBLIC KEY" in result["public_key"]

    def test_encrypt_for_owner(self):
        """Test owner encryption."""
        # Generate key pair for testing
        keys = ProxyEncryptionService.generate_key_pair()
        content = "test data for encryption"
        locator = "test-locator-123"

        result = ProxyEncryptionService.encrypt_for_owner(
            content, keys["public_key"], locator
        )

        assert "encrypted_content" in result
        assert "iv" in result
        assert "encrypted_key" in result
        assert "key_hash" in result
        assert "locator" in result
        assert "timestamp" in result
        assert "encryption_id" in result

        assert result["locator"] == locator
        assert len(result["encryption_id"]) > 0

    def test_generate_proxy_key(self):
        """Test proxy key generation."""
        # Generate owner and recipient key pairs
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        locator = "test-locator-456"

        result = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            locator,
            24  # 24 hours expiration
        )

        assert "proxy_id" in result
        assert "proxy_key_hash" in result
        assert "proxy_data" in result
        assert "locator" in result
        assert "owner_public_key" in result
        assert "recipient_public_key" in result
        assert "created_at" in result
        assert "expires_at" in result
        assert "is_revoked" in result
        assert "salt" in result

        assert result["locator"] == locator
        assert result["is_revoked"] == False
        assert result["recipient_public_key"] == recipient_keys["public_key"]

    def test_generate_proxy_key_expiration(self):
        """Test proxy key expiration time calculation."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        locator = "test-locator-789"
        expiration_hours = 48

        before_time = datetime.utcnow()
        result = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            locator,
            expiration_hours
        )
        after_time = datetime.utcnow()

        created_at = datetime.fromisoformat(result["created_at"])
        expires_at = datetime.fromisoformat(result["expires_at"])

        # Check that creation time is reasonable
        assert before_time <= created_at <= after_time

        # Check that expiration is approximately correct
        expected_expiration = created_at + timedelta(hours=expiration_hours)
        time_diff = abs((expires_at - expected_expiration).total_seconds())
        assert time_diff < 60  # Should be within 1 minute

    def test_re_encrypt_data(self):
        """Test data re-encryption using proxy key."""
        # Setup: create owner and recipient keys
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        content = "sensitive data to share"
        locator = "share-test-123"

        # Encrypt data for owner
        encrypted_data = ProxyEncryptionService.encrypt_for_owner(
            content, owner_keys["public_key"], locator
        )

        # Generate proxy key
        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            locator,
            24
        )

        # Re-encrypt data
        result = ProxyEncryptionService.re_encrypt_data(encrypted_data, proxy_key)

        assert "re_encrypted_content" in result
        assert "iv" in result
        assert "proxy_id" in result
        assert "original_encryption_id" in result
        assert "recipient_public_key" in result
        assert "locator" in result
        assert "re_encrypted_at" in result
        assert "re_encryption_id" in result

        assert result["proxy_id"] == proxy_key["proxy_id"]
        assert result["locator"] == locator
        assert result["original_encryption_id"] == encrypted_data["encryption_id"]

    def test_re_encrypt_data_revoked_proxy_key(self):
        """Test re-encryption fails with revoked proxy key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        content = "test content"
        locator = "revoke-test"

        encrypted_data = ProxyEncryptionService.encrypt_for_owner(
            content, owner_keys["public_key"], locator
        )

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            locator,
            24
        )

        # Revoke the proxy key
        proxy_key["is_revoked"] = True

        # Re-encryption should fail
        with pytest.raises(Exception, match="Proxy key has been revoked"):
            ProxyEncryptionService.re_encrypt_data(encrypted_data, proxy_key)

    def test_re_encrypt_data_expired_proxy_key(self):
        """Test re-encryption fails with expired proxy key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        content = "test content"
        locator = "expire-test"

        encrypted_data = ProxyEncryptionService.encrypt_for_owner(
            content, owner_keys["public_key"], locator
        )

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            locator,
            24
        )

        # Set expiration to past
        past_time = datetime.utcnow() - timedelta(hours=1)
        proxy_key["expires_at"] = past_time.isoformat()

        # Re-encryption should fail
        with pytest.raises(Exception, match="Proxy key has expired"):
            ProxyEncryptionService.re_encrypt_data(encrypted_data, proxy_key)

    def test_re_encrypt_data_locator_mismatch(self):
        """Test re-encryption fails with locator mismatch."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        content = "test content"

        encrypted_data = ProxyEncryptionService.encrypt_for_owner(
            content, owner_keys["public_key"], "locator-1"
        )

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "locator-2",  # Different locator
            24
        )

        # Re-encryption should fail due to locator mismatch
        with pytest.raises(Exception, match="Locator mismatch"):
            ProxyEncryptionService.re_encrypt_data(encrypted_data, proxy_key)

    def test_decrypt_for_recipient(self):
        """Test recipient decryption."""
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        # Mock re-encrypted data
        re_encrypted_data = {
            "re_encrypted_content": "bW9ja19lbmNyeXB0ZWRfZGF0YQ==",  # base64 encoded mock
            "locator": "test-locator",
            "re_encryption_id": "test-re-enc-id"
        }

        result = ProxyEncryptionService.decrypt_for_recipient(
            re_encrypted_data, recipient_keys["private_key"]
        )

        assert "decrypted_content" in result
        assert "locator" in result
        assert "decrypted_at" in result

        assert result["locator"] == "test-locator"
        # Note: In this simplified implementation, we return a placeholder
        assert "[DECRYPTED_CONTENT_PLACEHOLDER]" in result["decrypted_content"]

    def test_revoke_proxy_key(self):
        """Test proxy key revocation."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "revoke-test",
            24
        )

        # Initially should not be revoked
        assert proxy_key["is_revoked"] == False

        # Revoke the key
        result = ProxyEncryptionService.revoke_proxy_key(proxy_key, owner_keys["private_key"])

        assert result["revoked"] == True
        assert proxy_key["is_revoked"] == True
        assert "revoked_at" in proxy_key

    def test_revoke_proxy_key_unauthorized(self):
        """Test proxy key revocation fails with wrong private key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        wrong_keys = ProxyEncryptionService.generate_key_pair()

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "auth-test",
            24
        )

        # Revocation should fail with wrong private key
        with pytest.raises(Exception, match="Unauthorized"):
            ProxyEncryptionService.revoke_proxy_key(proxy_key, wrong_keys["private_key"])

    def test_verify_proxy_key_validity_valid(self):
        """Test proxy key validity verification for valid key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "valid-test",
            24
        )

        result = ProxyEncryptionService.verify_proxy_key_validity(proxy_key)

        assert result["valid"] == True
        assert "reason" not in result

    def test_verify_proxy_key_validity_revoked(self):
        """Test proxy key validity verification for revoked key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "revoked-test",
            24
        )

        # Revoke the key
        proxy_key["is_revoked"] = True

        result = ProxyEncryptionService.verify_proxy_key_validity(proxy_key)

        assert result["valid"] == False
        assert result["reason"] == "revoked"

    def test_verify_proxy_key_validity_expired(self):
        """Test proxy key validity verification for expired key."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        proxy_key = ProxyEncryptionService.generate_proxy_key(
            owner_keys["private_key"],
            recipient_keys["public_key"],
            "expired-test",
            1  # 1 hour expiration
        )

        # Set expiration to past
        past_time = datetime.utcnow() - timedelta(hours=2)
        proxy_key["expires_at"] = past_time.isoformat()

        result = ProxyEncryptionService.verify_proxy_key_validity(proxy_key)

        assert result["valid"] == False
        assert result["reason"] == "expired"

    def test_create_secure_share(self):
        """Test complete secure sharing workflow."""
        owner_keys = ProxyEncryptionService.generate_key_pair()
        recipient_keys = ProxyEncryptionService.generate_key_pair()
        content = "complete sharing test data"
        locator = "complete-test"

        result = ProxyEncryptionService.create_secure_share(
            content,
            locator,
            owner_keys["private_key"],
            recipient_keys["public_key"],
            48  # 48 hours expiration
        )

        assert "share_id" in result
        assert "locator" in result
        assert "encrypted_data" in result
        assert "proxy_key" in result
        assert "re_encrypted_data" in result
        assert "created_at" in result

        assert result["locator"] == locator

        # Verify encrypted data structure
        encrypted_data = result["encrypted_data"]
        assert "encryption_id" in encrypted_data
        assert "encrypted_content" in encrypted_data

        # Verify proxy key structure
        proxy_key = result["proxy_key"]
        assert "proxy_id" in proxy_key
        assert proxy_key["is_revoked"] == False

        # Verify re-encrypted data structure
        re_encrypted_data = result["re_encrypted_data"]
        assert "re_encryption_id" in re_encrypted_data
        assert re_encrypted_data["proxy_id"] == proxy_key["proxy_id"]

    def test_create_secure_share_invalid_keys(self):
        """Test secure share creation fails with invalid keys."""
        invalid_private_key = "invalid-private-key"
        recipient_keys = ProxyEncryptionService.generate_key_pair()

        with pytest.raises(Exception):
            ProxyEncryptionService.create_secure_share(
                "test content",
                "invalid-test",
                invalid_private_key,
                recipient_keys["public_key"],
                24
            )
