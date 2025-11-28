"""
API routes for AccessControl contract operations.

This module defines the FastAPI routes for blockchain access control endpoints.
"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from web3 import Web3
from app.schemas.blockchain import (
    DeployAccessControlResponse, RegisterDataRequest, AccessControlResponse,
    GrantAccessRequest, RevokeAccessRequest, CheckAccessRequest, AccessCheckResponse,
    ListAccessorsRequest, ListAccessorsResponse, GetDataOwnerRequest, GetDataOwnerResponse,
    MultiUserAccessRequest, MultiUserAccessResponse
)
from app.services.blockchain_service import BlockchainService
from app.api.dependencies import get_db
from app.config.settings import settings

router = APIRouter()


@router.post('/deploy/', response_model=DeployAccessControlResponse, tags=["Access Control"])
def deploy_access_control() -> DeployAccessControlResponse:
    """
    Deploy AccessControl contract to the blockchain.

    Returns:
        DeployAccessControlResponse: Contract address.
    """
    try:
        blockchain_service = BlockchainService()
        contract_address = blockchain_service.deploy_access_control()

        # Update settings with deployed contract address
        settings.access_control_address = contract_address

        return DeployAccessControlResponse(contract_address=contract_address)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to deploy contract: {str(e)}")


@router.post('/registerData/', response_model=AccessControlResponse, tags=["Access Control"])
def register_data(data: RegisterDataRequest) -> AccessControlResponse:
    """
    Register data in the AccessControl contract.

    Args:
        data (RegisterDataRequest): Data registration request.

    Returns:
        AccessControlResponse: Transaction hash.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        # Register data
        tx_hash = blockchain_service.register_data(data_id, from_account=data.from_account)

        return AccessControlResponse(transaction_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register data: {str(e)}")


@router.post('/grantAccess/', response_model=AccessControlResponse, tags=["Access Control"])
def grant_access(data: GrantAccessRequest) -> AccessControlResponse:
    """
    Grant access to a user for specific data.

    Args:
        data (GrantAccessRequest): Grant access request.

    Returns:
        AccessControlResponse: Transaction hash.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        # Grant access
        tx_hash = blockchain_service.grant_access(data.user, data_id, from_account=data.from_account)

        return AccessControlResponse(transaction_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to grant access: {str(e)}")


@router.post('/revokeAccess/', response_model=AccessControlResponse, tags=["Access Control"])
def revoke_access(data: RevokeAccessRequest) -> AccessControlResponse:
    """
    Revoke access from a user for specific data.

    Args:
        data (RevokeAccessRequest): Revoke access request.

    Returns:
        AccessControlResponse: Transaction hash.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        # Revoke access
        tx_hash = blockchain_service.revoke_access(data.user, data_id, from_account=data.from_account)

        return AccessControlResponse(transaction_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke access: {str(e)}")


@router.get('/checkAccess/', response_model=AccessCheckResponse, tags=["Access Control"])
def check_access(user: str, locator: str) -> AccessCheckResponse:
    """
    Check if a user has access to specific data.

    Args:
        user (str): User address to check.
        locator (str): Entity locator.

    Returns:
        AccessCheckResponse: Access check result.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=locator).hex()

        # Check access
        has_access = blockchain_service.has_access(user, data_id)

        return AccessCheckResponse(
            has_access=has_access,
            user=user,
            data_id=data_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check access: {str(e)}")


@router.get('/listAccessors/', response_model=ListAccessorsResponse, tags=["Access Control"])
def list_accessors(locator: str) -> ListAccessorsResponse:
    """
    List all users with access to specific data.

    Args:
        locator (str): Entity locator.

    Returns:
        ListAccessorsResponse: List of accessors.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=locator).hex()

        # Get accessors
        accessors = blockchain_service.list_accessors(data_id)
        total_count = blockchain_service.get_accessor_count(data_id)

        return ListAccessorsResponse(
            accessors=accessors,
            total_count=total_count,
            data_id=data_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list accessors: {str(e)}")


@router.get('/getDataOwner/', response_model=GetDataOwnerResponse, tags=["Access Control"])
def get_data_owner(locator: str) -> GetDataOwnerResponse:
    """
    Get the owner of specific data.

    Args:
        locator (str): Entity locator.

    Returns:
        GetDataOwnerResponse: Data owner information.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=locator).hex()

        # Get owner
        owner = blockchain_service.get_data_owner(data_id)

        return GetDataOwnerResponse(
            owner=owner,
            data_id=data_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get data owner: {str(e)}")


@router.post('/grantMultipleAccess/', response_model=MultiUserAccessResponse, tags=["Access Control"])
def grant_multiple_access(data: MultiUserAccessRequest) -> MultiUserAccessResponse:
    """
    Grant access to multiple users for specific data.

    Args:
        data (MultiUserAccessRequest): Multiple user access request.

    Returns:
        MultiUserAccessResponse: Results of all operations.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        successful_operations = []
        failed_operations = []

        for user in data.users:
            try:
                tx_hash = blockchain_service.grant_access(user, data_id, from_account=data.from_account)
                successful_operations.append({
                    "user": user,
                    "transaction_hash": tx_hash,
                    "operation": "grant_access"
                })
            except Exception as user_e:
                failed_operations.append({
                    "user": user,
                    "error": str(user_e),
                    "operation": "grant_access"
                })

        return MultiUserAccessResponse(
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            total_requested=len(data.users),
            successful_count=len(successful_operations)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to grant multiple access: {str(e)}")


@router.post('/revokeMultipleAccess/', response_model=MultiUserAccessResponse, tags=["Access Control"])
def revoke_multiple_access(data: MultiUserAccessRequest) -> MultiUserAccessResponse:
    """
    Revoke access from multiple users for specific data.

    Args:
        data (MultiUserAccessRequest): Multiple user access request.

    Returns:
        MultiUserAccessResponse: Results of all operations.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        successful_operations = []
        failed_operations = []

        for user in data.users:
            try:
                tx_hash = blockchain_service.revoke_access(user, data_id, from_account=data.from_account)
                successful_operations.append({
                    "user": user,
                    "transaction_hash": tx_hash,
                    "operation": "revoke_access"
                })
            except Exception as user_e:
                failed_operations.append({
                    "user": user,
                    "error": str(user_e),
                    "operation": "revoke_access"
                })

        return MultiUserAccessResponse(
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            total_requested=len(data.users),
            successful_count=len(successful_operations)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke multiple access: {str(e)}")


@router.post('/revokeAllAccess/', response_model=MultiUserAccessResponse, tags=["Access Control"])
def revoke_all_access(data: RegisterDataRequest) -> MultiUserAccessResponse:
    """
    Revoke access from all users for specific data.

    Args:
        data (RegisterDataRequest): Data with locator and from_account.

    Returns:
        MultiUserAccessResponse: Results of all operations.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        # Get all current accessors
        current_accessors = blockchain_service.list_accessors(data_id)

        successful_operations = []
        failed_operations = []

        for user in current_accessors:
            try:
                tx_hash = blockchain_service.revoke_access(user, data_id, from_account=data.from_account)
                successful_operations.append({
                    "user": user,
                    "transaction_hash": tx_hash,
                    "operation": "revoke_access"
                })
            except Exception as user_e:
                failed_operations.append({
                    "user": user,
                    "error": str(user_e),
                    "operation": "revoke_access"
                })

        return MultiUserAccessResponse(
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            total_requested=len(current_accessors),
            successful_count=len(successful_operations)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke all access: {str(e)}")


@router.post('/logAccess/', response_model=AccessControlResponse, tags=["Access Control"])
def log_access(data: CheckAccessRequest) -> AccessControlResponse:
    """
    Log an access attempt for audit purposes.

    Args:
        data (CheckAccessRequest): Access logging request.

    Returns:
        AccessControlResponse: Transaction hash.
    """
    try:
        blockchain_service = BlockchainService()

        # Generate dataId from locator
        data_id = Web3.keccak(text=data.locator).hex()

        # Log access
        tx_hash = blockchain_service.log_access(data.user, data_id)

        return AccessControlResponse(transaction_hash=tx_hash)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log access: {str(e)}")
