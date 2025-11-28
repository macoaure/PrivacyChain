"""
Pydantic schemas for blockchain operations.

This module defines the data models for blockchain-related API requests and responses.
"""
from pydantic import BaseModel, Field
from typing import Optional


class OnChainRequest(BaseModel):
    """
    Model for on-chain data registration.

    Attributes:
        content (str): Anonymized data to register on blockchain.
    """
    content: str = Field(..., title="Anonymized data", description="Result of secure anonymization.")


class RegisterOnChainResponse(BaseModel):
    """
    Response model for on-chain registration.

    Attributes:
        transaction_id (str): Blockchain transaction identifier.
    """
    transaction_id: str = Field(..., title="Transaction's Id registered", description="Transaction's Id registered")


class GetOnChainRequest(BaseModel):
    """
    Model for retrieving on-chain data.

    Attributes:
        transaction_id (str): Transaction identifier to query.
    """
    transaction_id: str = Field(..., title="Transaction ID", description="Transaction identifier")


class GetOnChainResponse(BaseModel):
    """
    Response model for on-chain data retrieval.

    Attributes:
        hash (str): Transaction hash.
        nonce (str): Transaction nonce.
        blockhash (str): Block hash.
        blockNumber (str): Block number.
        transactionIndex (str): Transaction index in block.
        FROM (str): Sender address.
        to (str): Receiver address.
        value (str): Transaction value.
        gas (str): Gas used.
        gasPrice (str): Gas price.
        input (str): Transaction input data.
        v (str): Recovery id.
        r (str): Signature r value.
        s (str): Signature s value.
    """
    hash: str = Field(..., title="Response content", description="")
    nonce: str = Field(..., title="Response content", description="")
    blockhash: str = Field(..., title="Response content", description="")
    blockNumber: str = Field(..., title="Response content", description="")
    transactionIndex: str = Field(..., title="Response content", description="")
    FROM: str = Field(..., title="Response content", description="")
    to: str = Field(..., title="Response content", description="")
    value: str = Field(..., title="Response content", description="")
    gas: str = Field(..., title="Response content", description="")
    gasPrice: str = Field(..., title="Response content", description="")
    input: str = Field(..., title="Response content", description="")
    v: str = Field(..., title="Response content", description="")
    r: str = Field(..., title="Response content", description="")
    s: str = Field(..., title="Response content", description="")


class IndexOnChainRequest(BaseModel):
    """
    Model for indexing data on-chain.

    Attributes:
        to_wallet (str): Destination wallet address.
        from_wallet (str): Source wallet address.
        content (str): Canonical data content.
        locator (str): Entity locator.
        datetime (str): Timestamp.
    """
    to_wallet: str = Field(..., title="Home wallet", description="Random home wallet address.")
    from_wallet: str = Field(..., title="Destination wallet", description="Random destination wallet address.")
    content: str = Field(..., title="Anonymized data", description="Result of secure anonymization.")
    locator: str = Field(..., title="Entity locator", description="Entity locator")
    datetime: str = Field(..., title="Timestamp", description="Timestamp")


class IndexOnChainSecureRequest(BaseModel):
    """
    Model for secure indexing on-chain with salt.

    Attributes:
        to_wallet (str): Destination wallet address.
        from_wallet (str): Source wallet address.
        content (str): Canonical data content.
        locator (str): Entity locator.
        datetime (str): Timestamp.
        salt (str): Salt for secure anonymization.
    """
    to_wallet: str = Field(..., title="Home wallet", description="Random home wallet address.")
    from_wallet: str = Field(..., title="Destination wallet", description="Random destination wallet address.")
    content: str = Field(..., title="Anonymized data", description="Result of secure anonymization.")
    locator: str = Field(..., title="Entity locator", description="Entity locator")
    datetime: str = Field(..., title="Timestamp", description="Timestamp")
    salt: str = Field(..., title="Salt", description="Salt value generated using UUIDv4.")


class UnindexOnChainRequest(BaseModel):
    """
    Model for unindexing data on-chain.

    Attributes:
        locator (str): Entity locator.
        datetime (str): Timestamp for specific unindexing.
    """
    locator: str = Field(..., title="Entity locator", description="Entity locator")
    datetime: str = Field(..., title="Timestamp", description="Timestamp")


class VerifySecureImmutableRequest(BaseModel):
    """
    Model for verifying secure immutable register.

    Attributes:
        transaction_id (str): Transaction identifier.
        content (str): Original content.
        salt (str): Salt used.
    """
    transaction_id: str = Field(..., title="Transaction ID", description="Transaction identifier")
    content: str = Field(..., title="Entity content for request",
                         description="Entity represent an object in JSON format in canonical form.")
    salt: str = Field(..., title="Salt", description="Salt value generated using UUIDv4.")


class RectifyOnChainRequest(BaseModel):
    """
    Model for rectifying data on-chain.

    Attributes:
        content (str): New content.
        salt (str): Salt.
        to_wallet (str): Destination wallet.
        from_wallet (str): Source wallet.
        locator (str): Entity locator.
        datetime (str): Timestamp.
    """
    content: str = Field(..., title="Entity content for request",
                        description="Entity represent an object in JSON format in canonical form.")
    salt: str = Field(..., title="Salt", description="Salt value generated using UUIDv4.")
    to_wallet: str = Field(..., title="Home wallet", description="Random home wallet address.")
    from_wallet: str = Field(..., title="Destination wallet", description="Random destination wallet address.")
    locator: str = Field(..., title="Entity locator", description="Entity locator")
    datetime: str = Field(..., title="Timestamp", description="Timestamp")


class RemoveOnChainRequest(BaseModel):
    """
    Model for removing data on-chain.

    Attributes:
        locator (str): Entity locator.
        datetime (str): Timestamp.
    """
    locator: str = Field(..., title="Entity locator", description="Entity locator")
    datetime: str = Field(..., title="Timestamp", description="Timestamp")


# Access Control Schemas

class DeployAccessControlResponse(BaseModel):
    """
    Response model for AccessControl contract deployment.

    Attributes:
        contract_address (str): Deployed contract address.
    """
    contract_address: str = Field(..., title="Contract Address", description="Address of the deployed AccessControl contract")


class RegisterDataRequest(BaseModel):
    """
    Model for registering data in AccessControl contract.

    Attributes:
        locator (str): Entity locator to generate dataId.
        from_account (Optional[str]): Account to send transaction from.
    """
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")
    from_account: Optional[str] = Field(None, title="From Account", description="Account address to send transaction from")


class AccessControlResponse(BaseModel):
    """
    Response model for access control operations.

    Attributes:
        transaction_hash (str): Transaction hash of the operation.
    """
    transaction_hash: str = Field(..., title="Transaction Hash", description="Hash of the blockchain transaction")


class GrantAccessRequest(BaseModel):
    """
    Model for granting access to data.

    Attributes:
        user (str): User address to grant access to.
        locator (str): Entity locator to generate dataId.
        from_account (Optional[str]): Account to send transaction from (must be data owner).
    """
    user: str = Field(..., title="User Address", description="Ethereum address of the user to grant access to")
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")
    from_account: Optional[str] = Field(None, title="From Account", description="Account address to send transaction from (must be data owner)")


class RevokeAccessRequest(BaseModel):
    """
    Model for revoking access to data.

    Attributes:
        user (str): User address to revoke access from.
        locator (str): Entity locator to generate dataId.
        from_account (Optional[str]): Account to send transaction from (must be data owner).
    """
    user: str = Field(..., title="User Address", description="Ethereum address of the user to revoke access from")
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")
    from_account: Optional[str] = Field(None, title="From Account", description="Account address to send transaction from (must be data owner)")


class CheckAccessRequest(BaseModel):
    """
    Model for checking user access to data.

    Attributes:
        user (str): User address to check.
        locator (str): Entity locator to generate dataId.
    """
    user: str = Field(..., title="User Address", description="Ethereum address of the user to check")
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")


class AccessCheckResponse(BaseModel):
    """
    Response model for access check operations.

    Attributes:
        has_access (bool): Whether the user has access or not.
        user (str): User address that was checked.
        data_id (str): Data ID that was checked.
    """
    has_access: bool = Field(..., title="Has Access", description="Whether the user has access to the data")
    user: str = Field(..., title="User Address", description="User address that was checked")
    data_id: str = Field(..., title="Data ID", description="Data ID that was checked")


class ListAccessorsRequest(BaseModel):
    """
    Model for listing data accessors.

    Attributes:
        locator (str): Entity locator to generate dataId.
    """
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")


class ListAccessorsResponse(BaseModel):
    """
    Response model for listing accessors.

    Attributes:
        accessors (list): List of user addresses with access.
        total_count (int): Total number of accessors.
        data_id (str): Data ID that was queried.
    """
    accessors: list = Field(..., title="Accessors", description="List of Ethereum addresses with access to the data")
    total_count: int = Field(..., title="Total Count", description="Total number of users with access")
    data_id: str = Field(..., title="Data ID", description="Data ID that was queried")


class GetDataOwnerRequest(BaseModel):
    """
    Model for getting data owner.

    Attributes:
        locator (str): Entity locator to generate dataId.
    """
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")


class GetDataOwnerResponse(BaseModel):
    """
    Response model for getting data owner.

    Attributes:
        owner (str): Owner address.
        data_id (str): Data ID that was queried.
    """
    owner: str = Field(..., title="Owner Address", description="Ethereum address of the data owner")
    data_id: str = Field(..., title="Data ID", description="Data ID that was queried")


class MultiUserAccessRequest(BaseModel):
    """
    Model for granting access to multiple users.

    Attributes:
        users (list): List of user addresses to grant access to.
        locator (str): Entity locator to generate dataId.
        from_account (Optional[str]): Account to send transactions from (must be data owner).
    """
    users: list = Field(..., title="User Addresses", description="List of Ethereum addresses to grant access to")
    locator: str = Field(..., title="Entity Locator", description="Entity locator used to generate dataId")
    from_account: Optional[str] = Field(None, title="From Account", description="Account address to send transactions from (must be data owner)")


class MultiUserAccessResponse(BaseModel):
    """
    Response model for multi-user access operations.

    Attributes:
        successful_operations (list): List of successful operations with transaction hashes.
        failed_operations (list): List of failed operations with error messages.
        total_requested (int): Total number of operations requested.
        successful_count (int): Number of successful operations.
    """
    successful_operations: list = Field(..., title="Successful Operations", description="List of successful operations")
    failed_operations: list = Field(..., title="Failed Operations", description="List of failed operations")
    total_requested: int = Field(..., title="Total Requested", description="Total number of operations requested")
    successful_count: int = Field(..., title="Successful Count", description="Number of successful operations")
