"""
Unit tests for utility functions and helpers.
"""
import pytest
from app.utils.helpers import generate_salt
from app.utils.enums import Blockchain, HashMethod, TypeAnonymization, CustomJSONEncoder


class TestHelpers:
    """Test cases for helper functions."""

    def test_generate_salt(self):
        """Test salt generation."""
        salt1 = generate_salt()
        salt2 = generate_salt()

        assert isinstance(salt1, str)
        assert len(salt1) == 36  # UUID4 length
        assert salt1 != salt2  # Should be unique

        # Test UUID4 format
        import uuid
        uuid.UUID(salt1)  # Should not raise exception


class TestEnums:
    """Test cases for enums."""

    def test_blockchain_enum(self):
        """Test Blockchain enum values."""
        assert Blockchain.ETHEREUM.value == "2"
        assert Blockchain.HYPERLEDGER.value == "1"
        assert Blockchain.BITCOIN.value == "3"

    def test_hash_method_enum(self):
        """Test HashMethod enum values."""
        assert HashMethod.SHA256.value == "3"
        assert HashMethod.MD5.value == "1"
        assert HashMethod.SHA512.value == "4"

    def test_type_anonymization_enum(self):
        """Test TypeAnonymization enum values."""
        assert TypeAnonymization.SIMPLE.value == "1"
        assert TypeAnonymization.SECURE.value == "2"


class TestCustomJSONEncoder:
    """Test cases for CustomJSONEncoder."""

    def test_encode_hexbytes(self):
        """Test encoding HexBytes objects."""
        import json
        from hexbytes import HexBytes
        encoder = CustomJSONEncoder()

        hex_data = HexBytes("0x1234567890abcdef")
        result = json.dumps(hex_data, cls=CustomJSONEncoder)
        assert result == '"0x1234567890abcdef"'

    def test_encode_string(self):
        """Test encoding regular strings."""
        import json
        encoder = CustomJSONEncoder()
        result = json.dumps("test_string", cls=CustomJSONEncoder)
        assert result == '"test_string"'

    def test_encode_other_types(self):
        """Test encoding other types."""
        import json
        encoder = CustomJSONEncoder()
        result = json.dumps(123, cls=CustomJSONEncoder)
        assert result == "123"
