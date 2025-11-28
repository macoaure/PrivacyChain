"""
Pydantic schemas for entity and anonymization requests.

This module defines the data models for API requests and responses related to data anonymization.
"""
from pydantic import BaseModel, Field
from typing import Optional


class Entity(BaseModel):
    """
    Model for entity content request.

    Attributes:
        content (str): Entity data in JSON format in canonical form.
    """
    content: str = Field(..., title="Entity content for request",
                         description="Entity represent an object in JSON format in canonical form.")


class SecureEntity(BaseModel):
    """
    Model for secure entity with salt.

    Attributes:
        content (str): Entity data in JSON format.
        salt (str): Salt value generated using UUIDv4.
    """
    content: str = Field(..., title="Entity content for request",
                         description="Entity represent an object in JSON format in canonical form.")
    salt: str = Field(..., title="Salt", description="Salt value generated using UUIDv4.")


class AnonymizeResponse(BaseModel):
    """
    Response model for anonymization operations.

    Attributes:
        content (str): Anonymized data.
    """
    content: str = Field(..., title="Anonymized data", description="Anonymized data")


class VerifyRequest(BaseModel):
    """
    Model for verification requests.

    Attributes:
        content (str): Original entity content.
        anonymized (str): Anonymized data result.
        salt (str): Salt used in anonymization.
    """
    content: str = Field(..., title="Entity content for request",
                         description="Entity represent an object in JSON format in canonical form.")
    anonymized: str = Field(..., title="Anonymized data", description="Result of secure anonymization.")
    salt: str = Field(..., title="Salt", description="Salt value generated using UUIDv4.")


class VerifyResponse(BaseModel):
    """
    Response model for verification operations.

    Attributes:
        result (bool): Verification result.
    """
    result: bool = Field(..., title="Verify Anonymized data", description="Verify Anonymized data")
