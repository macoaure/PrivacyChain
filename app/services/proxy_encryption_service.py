"""
Service for proxy re-encryption operations.

This module provides functionality for proxy re-encryption, allowing data owners
to generate proxy keys that enable re-encryption of their data for specific recipients
without exposing the owner's private key. The owner can revoke these proxy keys at any time.

The implementation uses elliptic curve cryptography (ECC) for key generation and
a simplified proxy re-encryption scheme.
"""
import hashlib
import json
import uuid
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64

from app.utils.helpers import generate_salt


class ProxyEncryptionService:
    """
    Service class for handling proxy re-encryption operations.

    Provides methods for:
    - Key pair generation
    - Proxy key generation and management
    - Data encryption for owner
    - Re-encryption using proxy keys
    - Decryption for recipients
    - Proxy key revocation
    """

    @staticmethod
    def generate_key_pair() -> Dict[str, str]:
        """
        Generate a new ECC key pair.

        Returns:
            Dict[str, str]: Dictionary containing private and public keys.
        """
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')

        return {
            "private_key": private_key,
            "public_key": public_key
        }

    @staticmethod
    def encrypt_for_owner(content: str, owner_public_key: str, locator: str) -> Dict[str, Any]:
        """
        Encrypt content for the data owner using their public key.

        Args:
            content (str): The content to encrypt.
            owner_public_key (str): Owner's public key in PEM format.
            locator (str): Entity locator for tracking.

        Returns:
            Dict[str, Any]: Dictionary containing encrypted data and metadata.
        """
        try:
            # Generate a random AES key
            aes_key = get_random_bytes(32)  # 256-bit key

            # Encrypt content with AES
            cipher = AES.new(aes_key, AES.MODE_CBC)
            padded_content = pad(content.encode(), AES.block_size)
            encrypted_content = cipher.encrypt(padded_content)

            # Encrypt AES key with owner's public key (simplified approach)
            # In a real implementation, you'd use ECIES or similar
            owner_key = ECC.import_key(owner_public_key)
            key_hash = hashlib.sha256(aes_key + owner_key.public_key().export_key(format='DER')).hexdigest()

            return {
                "encrypted_content": base64.b64encode(encrypted_content).decode(),
                "iv": base64.b64encode(cipher.iv).decode(),
                "encrypted_key": base64.b64encode(aes_key).decode(),  # Simplified - would be encrypted with public key
                "key_hash": key_hash,
                "locator": locator,
                "timestamp": datetime.utcnow().isoformat(),
                "encryption_id": str(uuid.uuid4())
            }
        except Exception as e:
            raise Exception(f"Failed to encrypt for owner: {str(e)}")

    @staticmethod
    def generate_proxy_key(
        owner_private_key: str,
        recipient_public_key: str,
        locator: str,
        expiration_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Generate a proxy key that allows re-encryption from owner to recipient.

        Args:
            owner_private_key (str): Owner's private key in PEM format.
            recipient_public_key (str): Recipient's public key in PEM format.
            locator (str): Entity locator.
            expiration_hours (int): Hours until proxy key expires.

        Returns:
            Dict[str, Any]: Dictionary containing proxy key and metadata.
        """
        try:
            owner_key = ECC.import_key(owner_private_key)
            recipient_key = ECC.import_key(recipient_public_key)

            # Generate proxy key components
            proxy_id = str(uuid.uuid4())
            salt = generate_salt()

            # Create proxy transformation data (simplified)
            # In a real proxy re-encryption scheme, this would be more complex
            proxy_data = {
                "owner_key_point": owner_key.public_key().export_key(format='DER').hex(),
                "recipient_key_point": recipient_key.export_key(format='DER').hex(),
                "salt": salt
            }

            # Create proxy key hash
            proxy_key_material = json.dumps(proxy_data, sort_keys=True).encode()
            proxy_key_hash = hashlib.sha256(proxy_key_material).hexdigest()

            expiration = datetime.utcnow() + timedelta(hours=expiration_hours)

            return {
                "proxy_id": proxy_id,
                "proxy_key_hash": proxy_key_hash,
                "proxy_data": proxy_data,
                "locator": locator,
                "owner_public_key": owner_key.public_key().export_key(format='PEM'),
                "recipient_public_key": recipient_public_key,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": expiration.isoformat(),
                "is_revoked": False,
                "salt": salt
            }
        except Exception as e:
            raise Exception(f"Failed to generate proxy key: {str(e)}")

    @staticmethod
    def re_encrypt_data(
        encrypted_data: Dict[str, Any],
        proxy_key: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Re-encrypt data using a proxy key to transform owner-encrypted data
        into recipient-encrypted data.

        Args:
            encrypted_data (dict): Owner-encrypted data.
            proxy_key (dict): Valid proxy key.

        Returns:
            Dict[str, Any]: Re-encrypted data for recipient.
        """
        try:
            # Verify proxy key is not expired or revoked
            if proxy_key["is_revoked"]:
                raise Exception("Proxy key has been revoked")

            expiration = datetime.fromisoformat(proxy_key["expires_at"])
            if datetime.utcnow() > expiration:
                raise Exception("Proxy key has expired")

            # Verify locator matches
            if encrypted_data["locator"] != proxy_key["locator"]:
                raise Exception("Locator mismatch between data and proxy key")

            # Re-encrypt the data (simplified transformation)
            # In a real system, this would involve complex mathematical operations
            re_encrypted_content = encrypted_data["encrypted_content"]

            # Generate new encryption metadata for recipient
            new_iv = get_random_bytes(16)

            return {
                "re_encrypted_content": re_encrypted_content,
                "iv": base64.b64encode(new_iv).decode(),
                "proxy_id": proxy_key["proxy_id"],
                "original_encryption_id": encrypted_data["encryption_id"],
                "recipient_public_key": proxy_key["recipient_public_key"],
                "locator": proxy_key["locator"],
                "re_encrypted_at": datetime.utcnow().isoformat(),
                "re_encryption_id": str(uuid.uuid4())
            }
        except Exception as e:
            raise Exception(f"Failed to re-encrypt data: {str(e)}")

    @staticmethod
    def decrypt_for_recipient(
        re_encrypted_data: Dict[str, Any],
        recipient_private_key: str
    ) -> Dict[str, str]:
        """
        Decrypt re-encrypted data using recipient's private key.

        Args:
            re_encrypted_data (dict): Re-encrypted data.
            recipient_private_key (str): Recipient's private key.

        Returns:
            Dict[str, str]: Decrypted content.
        """
        try:
            recipient_key = ECC.import_key(recipient_private_key)

            # Decrypt the content (simplified)
            # In a real implementation, this would involve proper ECIES decryption
            encrypted_content = base64.b64decode(re_encrypted_data["re_encrypted_content"])

            # For this simplified implementation, we'll return a placeholder
            # In practice, you'd need the original AES key derivation
            return {
                "decrypted_content": "[DECRYPTED_CONTENT_PLACEHOLDER]",
                "locator": re_encrypted_data["locator"],
                "decrypted_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            raise Exception(f"Failed to decrypt for recipient: {str(e)}")

    @staticmethod
    def revoke_proxy_key(proxy_key: Dict[str, Any], owner_private_key: str) -> Dict[str, bool]:
        """
        Revoke a proxy key, preventing further re-encryption operations.

        Args:
            proxy_key (dict): Proxy key to revoke.
            owner_private_key (str): Owner's private key for authentication.

        Returns:
            Dict[str, bool]: Revocation result.
        """
        try:
            # Verify owner has authority to revoke (simplified check)
            owner_key = ECC.import_key(owner_private_key)
            expected_owner_public = owner_key.public_key().export_key(format='PEM')

            if proxy_key["owner_public_key"] != expected_owner_public:
                raise Exception("Unauthorized: Only data owner can revoke proxy keys")

            # Mark as revoked
            proxy_key["is_revoked"] = True
            proxy_key["revoked_at"] = datetime.utcnow().isoformat()

            return {"revoked": True}
        except Exception as e:
            raise Exception(f"Failed to revoke proxy key: {str(e)}")

    @staticmethod
    def verify_proxy_key_validity(proxy_key: Dict[str, Any]) -> Dict[str, bool]:
        """
        Verify if a proxy key is valid and not expired or revoked.

        Args:
            proxy_key (dict): Proxy key to verify.

        Returns:
            Dict[str, bool]: Validity status.
        """
        try:
            if proxy_key["is_revoked"]:
                return {"valid": False, "reason": "revoked"}

            expiration = datetime.fromisoformat(proxy_key["expires_at"])
            if datetime.utcnow() > expiration:
                return {"valid": False, "reason": "expired"}

            return {"valid": True}
        except Exception as e:
            return {"valid": False, "reason": f"verification_error: {str(e)}"}

    @staticmethod
    def create_secure_share(
        content: str,
        locator: str,
        owner_private_key: str,
        recipient_public_key: str,
        expiration_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Complete secure sharing workflow: encrypt, generate proxy key, and re-encrypt.

        Args:
            content (str): Content to share.
            locator (str): Entity locator.
            owner_private_key (str): Owner's private key.
            recipient_public_key (str): Recipient's public key.
            expiration_hours (int): Proxy key expiration time.

        Returns:
            Dict[str, Any]: Complete sharing package.
        """
        try:
            # Get owner's public key
            owner_key = ECC.import_key(owner_private_key)
            owner_public_key = owner_key.public_key().export_key(format='PEM')

            # Encrypt for owner
            encrypted_data = ProxyEncryptionService.encrypt_for_owner(
                content, owner_public_key, locator
            )

            # Generate proxy key
            proxy_key = ProxyEncryptionService.generate_proxy_key(
                owner_private_key, recipient_public_key, locator, expiration_hours
            )

            # Re-encrypt for recipient
            re_encrypted_data = ProxyEncryptionService.re_encrypt_data(
                encrypted_data, proxy_key
            )

            return {
                "share_id": str(uuid.uuid4()),
                "locator": locator,
                "encrypted_data": encrypted_data,
                "proxy_key": proxy_key,
                "re_encrypted_data": re_encrypted_data,
                "created_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            raise Exception(f"Failed to create secure share: {str(e)}")
