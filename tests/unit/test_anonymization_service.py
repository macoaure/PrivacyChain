"""
Unit tests for the AnonymizationService.
"""
import pytest
from unittest.mock import patch
from app.services.anonymization_service import AnonymizationService


class TestAnonymizationService:
    """Test cases for AnonymizationService."""

    def test_simple_anonymize_sha256(self):
        """Test simple anonymization with SHA256."""
        content = "test_data"
        result = AnonymizationService.simple_anonymize(content, "SHA256")

        assert "content" in result
        assert isinstance(result["content"], str)
        assert len(result["content"]) == 64  # SHA256 hex length

    def test_simple_anonymize_md5(self):
        """Test simple anonymization with MD5."""
        content = "test_data"
        result = AnonymizationService.simple_anonymize(content, "MD5")

        assert "content" in result
        assert isinstance(result["content"], str)
        assert len(result["content"]) == 32  # MD5 hex length

    def test_simple_anonymize_invalid_hash(self):
        """Test simple anonymization with invalid hash method."""
        content = "test_data"

        with pytest.raises(ValueError, match="Unsupported hash method"):
            AnonymizationService.simple_anonymize(content, "INVALID")

    def test_secure_anonymize_with_provided_salt(self):
        """Test secure anonymization with provided salt."""
        content = "test_data"
        salt = "test_salt"
        result = AnonymizationService.secure_anonymize(content, salt, "SHA256")

        assert "content" in result
        assert isinstance(result["content"], str)
        # The result should be different from simple anonymization
        simple_result = AnonymizationService.simple_anonymize(content, "SHA256")
        assert result["content"] != simple_result["content"]

    def test_secure_anonymize_generate_salt(self):
        """Test secure anonymization with generated salt."""
        content = "test_data"
        result = AnonymizationService.secure_anonymize(content, hash_method="SHA256")

        assert "content" in result
        assert isinstance(result["content"], str)

    @patch('app.services.anonymization_service.AnonymizationService.simple_anonymize')
    def test_secure_anonymize_calls_simple_anonymize(self, mock_simple):
        """Test that secure anonymize calls simple anonymize."""
        mock_simple.return_value = {"content": "hashed"}
        content = "test_data"
        salt = "test_salt"

        result = AnonymizationService.secure_anonymize(content, salt, "SHA256")

        mock_simple.assert_called_once()
        assert result == {"content": "hashed"}

    def test_verify_secure_anonymize_valid(self):
        """Test verification of valid secure anonymization."""
        content = "test_data"
        salt = "test_salt"

        # First create the anonymized data
        anonymized_result = AnonymizationService.secure_anonymize(content, salt, "SHA256")
        anonymized = anonymized_result["content"]

        # Then verify it
        result = AnonymizationService.verify_secure_anonymize(content, anonymized, salt, "SHA256")

        assert result["result"] is True

    def test_verify_secure_anonymize_invalid(self):
        """Test verification of invalid secure anonymization."""
        content = "test_data"
        salt = "test_salt"
        wrong_anonymized = "wrong_hash"

        result = AnonymizationService.verify_secure_anonymize(content, wrong_anonymized, salt, "SHA256")

        assert result["result"] is False

    def test_get_hash_function_valid(self):
        """Test getting valid hash functions."""
        sha256_func = AnonymizationService._get_hash_function("SHA256")
        md5_func = AnonymizationService._get_hash_function("MD5")

        assert callable(sha256_func)
        assert callable(md5_func)

        # Test they work
        test_data = b"test"
        assert isinstance(sha256_func(test_data).hexdigest(), str)
        assert isinstance(md5_func(test_data).hexdigest(), str)

    def test_get_hash_function_invalid(self):
        """Test getting invalid hash function."""
        with pytest.raises(ValueError, match="Unsupported hash method"):
            AnonymizationService._get_hash_function("INVALID")
