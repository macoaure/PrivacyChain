"""
Service for data anonymization operations.

This module provides functions for simple and secure anonymization of data.
"""
import hashlib
import json
from typing import Dict, Any
from app.utils.helpers import generate_salt
from app.utils.enums import HashMethod


class AnonymizationService:
    """
    Service class for handling data anonymization.

    Provides methods for simple and secure anonymization using various hash methods.
    """

    @staticmethod
    def simple_anonymize(content: str, hash_method: str = "SHA256") -> Dict[str, str]:
        """
        Perform simple anonymization on the given content.

        Args:
            content (str): The content to anonymize.
            hash_method (str): The hash method to use (default: SHA256).

        Returns:
            Dict[str, str]: Dictionary containing the anonymized content.

        Raises:
            ValueError: If an unsupported hash method is provided.
        """
        hash_func = AnonymizationService._get_hash_function(hash_method)
        anonymized_data = hash_func(content.encode()).hexdigest()
        return {"content": anonymized_data}

    @staticmethod
    def secure_anonymize(content: str, salt: Optional[str] = None, hash_method: str = "SHA256") -> Dict[str, str]:
        """
        Perform secure anonymization with salt.

        Args:
            content (str): The content to anonymize.
            salt (Optional[str]): Salt to use; generates one if None.
            hash_method (str): The hash method to use (default: SHA256).

        Returns:
            Dict[str, str]: Dictionary containing the anonymized content.
        """
        if salt is None:
            salt = generate_salt()

        # Combine content with salt
        salted_content = f"{content[:-1]}, salt:{salt}}}"

        return AnonymizationService.simple_anonymize(salted_content, hash_method)

    @staticmethod
    def verify_secure_anonymize(content: str, anonymized: str, salt: str, hash_method: str = "SHA256") -> Dict[str, bool]:
        """
        Verify if the anonymized data matches the secure anonymization of content with salt.

        Args:
            content (str): Original content.
            anonymized (str): Anonymized data to verify.
            salt (str): Salt used in anonymization.
            hash_method (str): Hash method used.

        Returns:
            Dict[str, bool]: Dictionary with verification result.
        """
        result = AnonymizationService.secure_anonymize(content, salt, hash_method)
        is_valid = result["content"] == anonymized
        return {"result": is_valid}

    @staticmethod
    def _get_hash_function(hash_method: str):
        """
        Get the hash function based on the method name.

        Args:
            hash_method (str): Name of the hash method.

        Returns:
            Callable: The hash function.

        Raises:
            ValueError: If hash method is not supported.
        """
        methods = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }
        if hash_method not in methods:
            raise ValueError(f"Unsupported hash method: {hash_method}")
        return methods[hash_method]
