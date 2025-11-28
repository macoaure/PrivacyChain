"""
API dependencies.

This module provides dependency injection functions for the API.
"""
from typing import Generator
from sqlalchemy.orm import Session
from app.database.connection import get_database_session


def get_db() -> Generator[Session, None, None]:
    """
    Dependency to get a database session.

    Yields:
        Session: SQLAlchemy database session.
    """
    yield from get_database_session()
