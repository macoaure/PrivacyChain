"""
API routes for proxy re-encryption operations.

This module defines the FastAPI routes for proxy re-encryption endpoints,
allowing secure data sharing with revocable access control.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.schemas.proxy_encryption import (
    KeyPairResponse, EncryptForOwnerRequest, EncryptForOwnerResponse,
    GenerateProxyKeyRequest, ProxyKeyResponse, ReEncryptDataRequest, ReEncryptDataResponse,
    DecryptForRecipientRequest, DecryptForRecipientResponse, RevokeProxyKeyRequest,
    RevokeProxyKeyResponse, VerifyProxyKeyRequest, VerifyProxyKeyResponse,
    SecureShareRequest, SecureShareResponse, ProxyShareMetrics
)
from app.services.proxy_encryption_service import ProxyEncryptionService
from app.services.blockchain_service import BlockchainService
from app.crud.proxy_encryption_crud import (
    ProxyKeyCRUD, EncryptedDataCRUD, ReEncryptedDataCRUD,
    ShareRecordCRUD, ProxyMetricsCRUD
)
from app.api.dependencies import get_db
from web3 import Web3
from datetime import datetime
import uuid

router = APIRouter()


@router.post('/generateKeyPair/', response_model=KeyPairResponse, tags=["Proxy Encryption"])
def generate_key_pair() -> KeyPairResponse:
    """
    Generate a new ECC key pair for proxy re-encryption.

    Returns:
        KeyPairResponse: Generated private and public key pair.
    """
    try:
        result = ProxyEncryptionService.generate_key_pair()
        return KeyPairResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/encryptForOwner/', response_model=EncryptForOwnerResponse, tags=["Proxy Encryption"])
def encrypt_for_owner(
    data: EncryptForOwnerRequest,
    db: Session = Depends(get_db)
) -> EncryptForOwnerResponse:
    """
    Encrypt content for the data owner using their public key.

    Args:
        data: Encryption request containing content, owner public key, and locator.
        db: Database session.

    Returns:
        EncryptForOwnerResponse: Encrypted data and metadata.
    """
    try:
        # Encrypt the data
        result = ProxyEncryptionService.encrypt_for_owner(
            data.content, data.owner_public_key, data.locator
        )

        # Store encrypted data in database
        EncryptedDataCRUD.create_encrypted_data(db, result)

        return EncryptForOwnerResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/generateProxyKey/', response_model=ProxyKeyResponse, tags=["Proxy Encryption"])
def generate_proxy_key(
    data: GenerateProxyKeyRequest,
    db: Session = Depends(get_db)
) -> ProxyKeyResponse:
    """
    Generate a proxy key for secure data sharing.

    Args:
        data: Proxy key generation request.
        db: Database session.

    Returns:
        ProxyKeyResponse: Generated proxy key information.
    """
    try:
        # Generate proxy key
        proxy_key = ProxyEncryptionService.generate_proxy_key(
            data.owner_private_key,
            data.recipient_public_key,
            data.locator,
            data.expiration_hours
        )

        # Store proxy key in database
        ProxyKeyCRUD.create_proxy_key(db, proxy_key)

        # Register proxy key on blockchain
        try:
            blockchain_service = BlockchainService()
            data_id = Web3.keccak(text=data.locator).hex()

            # Convert expiration to timestamp
            expires_at = datetime.fromisoformat(proxy_key["expires_at"])
            expiration_timestamp = int(expires_at.timestamp())

            # Get owner's public key from private key to derive address
            from Crypto.PublicKey import ECC
            owner_key = ECC.import_key(data.owner_private_key)

            # Generate proxy key on blockchain (simplified - would need proper address derivation)
            tx_hash = blockchain_service.generate_proxy_key_on_chain(\n                proxy_key[\"proxy_id\"],\n                data_id,\n                \"0x\" + proxy_key[\"recipient_public_key\"][-40:],  # Simplified address derivation\n                proxy_key[\"proxy_key_hash\"],\n                expiration_timestamp\n            )\n            \n            proxy_key[\"blockchain_tx\"] = tx_hash\n        except Exception as blockchain_error:\n            # Log blockchain error but don't fail the entire operation\n            print(f\"Blockchain registration failed: {blockchain_error}\")\n        \n        # Return only the response fields\n        response_data = {\n            \"proxy_id\": proxy_key[\"proxy_id\"],\n            \"proxy_key_hash\": proxy_key[\"proxy_key_hash\"],\n            \"locator\": proxy_key[\"locator\"],\n            \"owner_public_key\": proxy_key[\"owner_public_key\"],\n            \"recipient_public_key\": proxy_key[\"recipient_public_key\"],\n            \"created_at\": proxy_key[\"created_at\"],\n            \"expires_at\": proxy_key[\"expires_at\"],\n            \"is_revoked\": proxy_key[\"is_revoked\"]\n        }\n        \n        return ProxyKeyResponse(**response_data)\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.post('/reEncryptData/', response_model=ReEncryptDataResponse, tags=[\"Proxy Encryption\"])\ndef re_encrypt_data(\n    data: ReEncryptDataRequest,\n    db: Session = Depends(get_db)\n) -> ReEncryptDataResponse:\n    \"\"\"\n    Re-encrypt owner-encrypted data using a proxy key.\n    \n    Args:\n        data: Re-encryption request with encrypted data and proxy key.\n        db: Database session.\n    \n    Returns:\n        ReEncryptDataResponse: Re-encrypted data for recipient.\n    \"\"\"\n    try:\n        # Verify proxy key exists and is valid\n        proxy_key_record = ProxyKeyCRUD.get_proxy_key(db, data.proxy_key[\"proxy_id\"])\n        if not proxy_key_record:\n            raise HTTPException(status_code=404, detail=\"Proxy key not found\")\n        \n        if proxy_key_record.is_revoked:\n            raise HTTPException(status_code=403, detail=\"Proxy key has been revoked\")\n        \n        if datetime.utcnow() > proxy_key_record.expires_at:\n            raise HTTPException(status_code=403, detail=\"Proxy key has expired\")\n        \n        # Perform re-encryption\n        result = ProxyEncryptionService.re_encrypt_data(\n            data.encrypted_data, data.proxy_key\n        )\n        \n        # Store re-encrypted data\n        ReEncryptedDataCRUD.create_re_encrypted_data(db, result)\n        \n        return ReEncryptDataResponse(**result)\n    except HTTPException:\n        raise\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.post('/decryptForRecipient/', response_model=DecryptForRecipientResponse, tags=[\"Proxy Encryption\"])\ndef decrypt_for_recipient(\n    data: DecryptForRecipientRequest,\n    db: Session = Depends(get_db)\n) -> DecryptForRecipientResponse:\n    \"\"\"\n    Decrypt re-encrypted data using recipient's private key.\n    \n    Args:\n        data: Decryption request with re-encrypted data and recipient private key.\n        db: Database session.\n    \n    Returns:\n        DecryptForRecipientResponse: Decrypted content.\n    \"\"\"\n    try:\n        result = ProxyEncryptionService.decrypt_for_recipient(\n            data.re_encrypted_data, data.recipient_private_key\n        )\n        return DecryptForRecipientResponse(**result)\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.post('/revokeProxyKey/', response_model=RevokeProxyKeyResponse, tags=[\"Proxy Encryption\"])\ndef revoke_proxy_key(\n    data: RevokeProxyKeyRequest,\n    db: Session = Depends(get_db)\n) -> RevokeProxyKeyResponse:\n    \"\"\"\n    Revoke a proxy key, preventing further re-encryption operations.\n    \n    Args:\n        data: Revocation request with proxy key and owner private key.\n        db: Database session.\n    \n    Returns:\n        RevokeProxyKeyResponse: Revocation result.\n    \"\"\"\n    try:\n        # Verify proxy key exists\n        proxy_key_record = ProxyKeyCRUD.get_proxy_key(db, data.proxy_key[\"proxy_id\"])\n        if not proxy_key_record:\n            raise HTTPException(status_code=404, detail=\"Proxy key not found\")\n        \n        # Perform revocation\n        result = ProxyEncryptionService.revoke_proxy_key(\n            data.proxy_key, data.owner_private_key\n        )\n        \n        # Update database\n        ProxyKeyCRUD.revoke_proxy_key(db, data.proxy_key[\"proxy_id\"])\n        \n        # Deactivate related shares\n        ShareRecordCRUD.deactivate_shares_by_proxy(db, data.proxy_key[\"proxy_id\"])\n        \n        # Revoke on blockchain\n        try:\n            blockchain_service = BlockchainService()\n            tx_hash = blockchain_service.revoke_proxy_key_on_chain(data.proxy_key[\"proxy_id\"])\n            result[\"blockchain_tx\"] = tx_hash\n        except Exception as blockchain_error:\n            print(f\"Blockchain revocation failed: {blockchain_error}\")\n        \n        return RevokeProxyKeyResponse(**result)\n    except HTTPException:\n        raise\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.post('/verifyProxyKey/', response_model=VerifyProxyKeyResponse, tags=[\"Proxy Encryption\"])\ndef verify_proxy_key(\n    data: VerifyProxyKeyRequest,\n    db: Session = Depends(get_db)\n) -> VerifyProxyKeyResponse:\n    \"\"\"\n    Verify if a proxy key is valid and not expired or revoked.\n    \n    Args:\n        data: Verification request with proxy key.\n        db: Database session.\n    \n    Returns:\n        VerifyProxyKeyResponse: Validity status.\n    \"\"\"\n    try:\n        # Check database status\n        proxy_key_record = ProxyKeyCRUD.get_proxy_key(db, data.proxy_key[\"proxy_id\"])\n        if not proxy_key_record:\n            return VerifyProxyKeyResponse(valid=False, reason=\"not_found\")\n        \n        # Perform verification\n        result = ProxyEncryptionService.verify_proxy_key_validity(data.proxy_key)\n        \n        # Cross-check with blockchain if available\n        try:\n            blockchain_service = BlockchainService()\n            blockchain_valid = blockchain_service.is_proxy_key_valid_on_chain(data.proxy_key[\"proxy_id\"])\n            if not blockchain_valid and result[\"valid\"]:\n                result = {\"valid\": False, \"reason\": \"revoked_on_chain\"}\n        except Exception:\n            pass  # Blockchain check is optional\n        \n        return VerifyProxyKeyResponse(**result)\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.post('/createSecureShare/', response_model=SecureShareResponse, tags=[\"Proxy Encryption\"])\ndef create_secure_share(\n    data: SecureShareRequest,\n    db: Session = Depends(get_db)\n) -> SecureShareResponse:\n    \"\"\"\n    Complete secure sharing workflow: encrypt, generate proxy key, and re-encrypt.\n    \n    Args:\n        data: Secure sharing request.\n        db: Database session.\n    \n    Returns:\n        SecureShareResponse: Complete sharing package.\n    \"\"\"\n    try:\n        # Perform complete secure sharing\n        result = ProxyEncryptionService.create_secure_share(\n            data.content,\n            data.locator,\n            data.owner_private_key,\n            data.recipient_public_key,\n            data.expiration_hours\n        )\n        \n        # Store all components in database\n        EncryptedDataCRUD.create_encrypted_data(db, result[\"encrypted_data\"])\n        ProxyKeyCRUD.create_proxy_key(db, result[\"proxy_key\"])\n        ReEncryptedDataCRUD.create_re_encrypted_data(db, result[\"re_encrypted_data\"])\n        \n        # Create share record\n        share_record_data = {\n            \"share_id\": result[\"share_id\"],\n            \"locator\": result[\"locator\"],\n            \"owner_public_key\": result[\"proxy_key\"][\"owner_public_key\"],\n            \"recipient_public_key\": result[\"proxy_key\"][\"recipient_public_key\"],\n            \"encryption_id\": result[\"encrypted_data\"][\"encryption_id\"],\n            \"proxy_id\": result[\"proxy_key\"][\"proxy_id\"],\n            \"re_encryption_id\": result[\"re_encrypted_data\"][\"re_encryption_id\"],\n            \"encrypted_data\": result[\"encrypted_data\"],\n            \"re_encrypted_data\": result[\"re_encrypted_data\"]\n        }\n        ShareRecordCRUD.create_share_record(db, share_record_data)\n        \n        return SecureShareResponse(**result)\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.get('/proxyMetrics/', response_model=ProxyShareMetrics, tags=[\"Proxy Encryption\"])\ndef get_proxy_metrics(\n    locator: str = None,\n    db: Session = Depends(get_db)\n) -> ProxyShareMetrics:\n    \"\"\"\n    Get proxy sharing metrics and analytics.\n    \n    Args:\n        locator: Optional locator to filter metrics.\n        db: Database session.\n    \n    Returns:\n        ProxyShareMetrics: Metrics data.\n    \"\"\"\n    try:\n        result = ProxyMetricsCRUD.get_proxy_metrics(db, locator)\n        return result\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.get('/activeProxyKeys/{locator}', tags=[\"Proxy Encryption\"])\ndef get_active_proxy_keys(\n    locator: str,\n    db: Session = Depends(get_db)\n) -> Dict[str, Any]:\n    \"\"\"\n    Get all active proxy keys for a specific locator.\n    \n    Args:\n        locator: Entity locator.\n        db: Database session.\n    \n    Returns:\n        Dict containing active proxy keys.\n    \"\"\"\n    try:\n        proxy_keys = ProxyKeyCRUD.get_active_proxy_keys(db, locator)\n        \n        result = {\n            \"locator\": locator,\n            \"active_count\": len(proxy_keys),\n            \"proxy_keys\": [\n                {\n                    \"proxy_id\": pk.proxy_id,\n                    \"recipient_public_key\": pk.recipient_public_key,\n                    \"created_at\": pk.created_at.isoformat(),\n                    \"expires_at\": pk.expires_at.isoformat()\n                } for pk in proxy_keys\n            ]\n        }\n        \n        return result\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))\n\n\n@router.delete('/revokeAllProxyKeys/{locator}', tags=[\"Proxy Encryption\"])\ndef revoke_all_proxy_keys_for_locator(\n    locator: str,\n    owner_public_key: str,\n    db: Session = Depends(get_db)\n) -> Dict[str, Any]:\n    \"\"\"\n    Revoke all proxy keys for a specific locator and owner.\n    \n    Args:\n        locator: Entity locator.\n        owner_public_key: Owner's public key for verification.\n        db: Database session.\n    \n    Returns:\n        Dict with revocation results.\n    \"\"\"\n    try:\n        # Revoke in database\n        count = ProxyKeyCRUD.revoke_all_proxy_keys_for_locator(db, locator, owner_public_key)\n        \n        return {\n            \"locator\": locator,\n            \"revoked_count\": count,\n            \"message\": f\"Revoked {count} proxy keys for locator {locator}\"\n        }\n    except Exception as e:\n        raise HTTPException(status_code=500, detail=str(e))"
