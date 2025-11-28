"""
Database model for tracking personal data entries.

This module defines the Tracking SQLAlchemy model.
"""
from sqlalchemy import Column, Integer, String
from app.database.connection import Base


class Tracking(Base):
    """
    SQLAlchemy model for tracking table.

    Represents metadata for tracking personal data persisted in the blockchain.

    Attributes:
        tracking_id (int): Primary key, auto-incremented.
        canonical_data (str): Original personal data in canonical format.
        anonymized_data (str): Anonymized version of the personal data.
        blockchain_id (int): Identifier for the blockchain used.
        transaction_id (str): Blockchain transaction identifier.
        salt (str): Random salt used in anonymization.
        hash_method (str): Hash method used for anonymization.
        tracking_dt (str): Timestamp of when the data was tracked.
        locator (str): Identifier for the entity holding the personal data.
    """
    __tablename__ = "tracking"

    tracking_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    canonical_data = Column(String)
    anonymized_data = Column(String)
    blockchain_id = Column(Integer, index=True)
    transaction_id = Column(String)
    salt = Column(String)
    hash_method = Column(String)
    tracking_dt = Column(String)
    locator = Column(String)
