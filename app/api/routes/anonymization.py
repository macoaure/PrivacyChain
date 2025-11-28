"""
API routes for anonymization operations.

This module defines the FastAPI routes for data anonymization endpoints.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.schemas.entity import Entity, SecureEntity, AnonymizeResponse, VerifyRequest, VerifyResponse
from app.services.anonymization_service import AnonymizationService
from app.api.dependencies import get_db

router = APIRouter()


@router.post('/simpleAnonymize/', response_model=AnonymizeResponse, tags=["Pure Functions"])
def simple_anonymize(
    data: Entity,
    hash_method: str = "SHA256",
    db: Session = Depends(get_db)
) -> AnonymizeResponse:
    """
    Perform simple anonymization on the provided entity content.

    A = α(D, h)
    Anonymizes D by generating A through hash function h (optional), default SHA256.

    Args:
        data (Entity): The entity data to anonymize.
        hash_method (str): Hash method to use.
        db (Session): Database session (dependency).

    Returns:
        AnonymizeResponse: The anonymized data.
    """
    try:
        result = AnonymizationService.simple_anonymize(data.content, hash_method)
        return AnonymizeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/secureAnonymize/', response_model=AnonymizeResponse, tags=["Operations"])
def secure_anonymize(
    data: SecureEntity,
    hash_method: str = "SHA256",
    db: Session = Depends(get_db)
) -> AnonymizeResponse:
    """
    Perform secure anonymization with salt.

    A = γ(D, s, h)
    Anonymizes D (with a salt 's') by generating A through hash function h (optional), default SHA256.

    Args:
        data (SecureEntity): The entity data with salt.
        hash_method (str): Hash method to use.
        db (Session): Database session (dependency).

    Returns:
        AnonymizeResponse: The anonymized data.
    """
    try:
        result = AnonymizationService.secure_anonymize(data.content, data.salt, hash_method)
        return AnonymizeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/verifySecureAnonymize/', response_model=VerifyResponse, tags=["Pure Functions"])
def verify_secure_anonymize(
    data: VerifyRequest,
    hash_method: str = "SHA256",
    db: Session = Depends(get_db)
) -> VerifyResponse:
    """
    Verify whether the provided anonymized data is the result of secure anonymization.

    Γ(A, D, s, h)
    Verify whether the value 'A' is the result of anonymizing D with salt s and hash h.

    Args:
        data (VerifyRequest): Verification data.
        hash_method (str): Hash method used.
        db (Session): Database session (dependency).

    Returns:
        VerifyResponse: Verification result.
    """
    try:
        result = AnonymizationService.verify_secure_anonymize(data.content, data.anonymized, data.salt, hash_method)
        return VerifyResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
