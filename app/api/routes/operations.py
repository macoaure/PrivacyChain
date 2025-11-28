"""
API routes for blockchain operations.

This module defines the FastAPI routes for blockchain-related endpoints.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.schemas.blockchain import (
    OnChainRequest, RegisterOnChainResponse, GetOnChainRequest, GetOnChainResponse,
    IndexOnChainRequest, IndexOnChainSecureRequest, UnindexOnChainRequest,
    VerifySecureImmutableRequest, RectifyOnChainRequest, RemoveOnChainRequest
)
from app.services.blockchain_service import BlockchainService
from app.services.tracking_service import TrackingService
from app.api.dependencies import get_db

router = APIRouter()
tracking_service = TrackingService()


@router.post('/registerOnChain/', response_model=RegisterOnChainResponse, tags=["Operations"])
def register_on_chain(data: OnChainRequest, db: Session = Depends(get_db)) -> RegisterOnChainResponse:
    """
    Persist anonymized data in the blockchain.

    T_β = W(d, β)
    Persist array bytes d in blockchain β.

    Args:
        data (OnChainRequest): Data to register.
        db (Session): Database session.

    Returns:
        RegisterOnChainResponse: Transaction ID.
    """
    try:
        blockchain_service = BlockchainService()
        result = blockchain_service.register_on_chain(data.content)
        return RegisterOnChainResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/getOnChain/', response_model=GetOnChainResponse, tags=["Operations"])
def get_on_chain(data: GetOnChainRequest, db: Session = Depends(get_db)) -> GetOnChainResponse:
    """
    Retrieve data from the blockchain.

    d = R(T_β, β)
    Get d bytes array registered under transaction T_β in blockchain β.

    Args:
        data (GetOnChainRequest): Transaction to retrieve.
        db (Session): Database session.

    Returns:
        GetOnChainResponse: Transaction details.
    """
    try:
        blockchain_service = BlockchainService()
        result = blockchain_service.get_on_chain(data.transaction_id)
        return GetOnChainResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/indexOnChain/', tags=["Operations"])
def index_on_chain(data: IndexOnChainRequest, db: Session = Depends(get_db)):
    """
    Record data in the blockchain with timestamp.

    I(L_E, t, d, β)
    Records in blockchain β the data d of entity E identified by locator L_E, associating timestamp t.

    Args:
        data (IndexOnChainRequest): Indexing data.
        db (Session): Database session.

    Returns:
        dict: Created tracking entry.
    """
    try:
        result = tracking_service.index_on_chain(db, data.content, data.locator)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post('/indexSecureOnChain/', tags=["Operations"])
def index_secure_on_chain(data: IndexOnChainSecureRequest, db: Session = Depends(get_db)):
    """
    Record data securely in the blockchain.

    Args:
        data (IndexOnChainSecureRequest): Secure indexing data.
        db (Session): Database session.

    Returns:
        dict: Created tracking entry.
    """
    try:
        result = tracking_service.index_secure_on_chain(db, data.content, data.locator, data.salt)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post('/unindexOnChain/', tags=["Operations"])
def unindex_on_chain(data: UnindexOnChainRequest, db: Session = Depends(get_db)):
    """
    Dissociate previous indexing for locator.

    Δ(L_E, t)
    Dissociation of previous indexation on-chain for L_E locator in 't' moment.

    Args:
        data (UnindexOnChainRequest): Unindexing data.
        db (Session): Database session.

    Returns:
        dict: Deletion result.
    """
    try:
        result = tracking_service.unindex_on_chain(db, data.locator, data.datetime)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get('/verifySecureImmutableRegister/', tags=["Operations"])
def verify_secure_immutable_register(data: VerifySecureImmutableRequest, db: Session = Depends(get_db)):
    """
    Verify secure immutable register.

    Args:
        data (VerifySecureImmutableRequest): Verification data.
        db (Session): Database session.

    Returns:
        dict: Verification result.
    """
    try:
        blockchain_service = BlockchainService()
        result = blockchain_service.verify_secure_immutable_register(
            data.transaction_id, data.content, data.salt
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/rectifyOnChain/', tags=["Transactions"])
def rectify_on_chain(data: RectifyOnChainRequest, db: Session = Depends(get_db)):
    """
    Rectify data on-chain.

    Args:
        data (RectifyOnChainRequest): Rectification data.
        db (Session): Database session.

    Returns:
        dict: New tracking entry.
    """
    try:
        result = tracking_service.rectify_on_chain(db, data.content, data.salt, data.locator, data.datetime)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/removeOnChain/', tags=["Transactions"])
def remove_on_chain(data: RemoveOnChainRequest, db: Session = Depends(get_db)):
    """
    Remove data on-chain.

    Args:
        data (RemoveOnChainRequest): Removal data.
        db (Session): Database session.

    Returns:
        dict: Deletion result.
    """
    try:
        result = tracking_service.remove_on_chain(db, data.locator, data.datetime)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
