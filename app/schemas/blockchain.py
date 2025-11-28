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
