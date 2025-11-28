"""
Pydantic schemas for tracking data.

This module defines the data models for tracking database operations.
"""
from pydantic import BaseModel
from typing import List, Optional


class TrackingBase(BaseModel):
    """
    Base schema for tracking data.

    Attributes:
        canonical_data (str): Original personal data.
        anonymized_data (str): Anonymized data.
        blockchain_id (int): Blockchain identifier.
        transaction_id (str): Transaction identifier.
        salt (str): Salt used.
        hash_method (str): Hash method used.
        tracking_dt (str): Tracking timestamp.
        locator (str): Entity locator.
    """
    canonical_data: str
    anonymized_data: str
    blockchain_id: int
    transaction_id: str
    salt: str
    hash_method: str
    tracking_dt: str
    locator: str


class TrackingCreate(TrackingBase):
    """
    Schema for creating a new tracking entry.
    """
    pass


class Tracking(TrackingBase):
    """
    Schema for tracking data with ID.

    Attributes:
        tracking_id (int): Unique tracking identifier.
    """
    tracking_id: int

    class Config:
        orm_mode = True


class TrackingList(BaseModel):
    """
    Schema for a list of tracking entries.

    Attributes:
        trackings (List[Tracking]): List of tracking objects.
    """
    trackings: List[Tracking]
