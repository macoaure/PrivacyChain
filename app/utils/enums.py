"""
Enumerations used throughout the PrivacyChain application.

This module defines various enums for blockchain types, classification types,
anonymization types, and hash methods.
"""
import json
from enum import Enum, unique
from typing import Any


@unique
class Blockchain(str, Enum):
    """Enumeration of supported blockchains."""
    HYPERLEDGER = "1"
    ETHEREUM = "2"
    BITCOIN = "3"


@unique
class TypeClassification(str, Enum):
    """Enumeration of classification types."""
    EXPANDED = "1"
    SUMMARIZED = "2"


@unique
class TypeAnonymization(str, Enum):
    """Enumeration of anonymization types."""
    SIMPLE = "1"
    SECURE = "2"


@unique
class HashMethod(str, Enum):
    """Enumeration of supported hash methods."""
    MD5 = "1"
    SHA1 = "2"
    SHA256 = "3"
    SHA512 = "4"


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for handling HexBytes objects.

    This encoder converts HexBytes to their hexadecimal string representation.
    """

    def default(self, obj: Any) -> Any:
        """
        Override the default method to handle special object types.

        Args:
            obj: The object to encode.

        Returns:
            Any: The encoded representation.
        """
        if hasattr(obj, 'hex'):
            return "0x" + obj.hex()
        return super().default(obj)
