"""
Database connection and session management.

This module sets up the SQLAlchemy engine, session, and base class for the database.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator
from app.config.settings import settings

# Create the SQLAlchemy engine
engine = create_engine(settings.database_url)

# Create a session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Create all tables
Base.metadata.create_all(bind=engine)


def get_database_session() -> Generator[Session, None, None]:
    """
    Dependency function to get a database session.

    Yields:
        Session: A SQLAlchemy session object.

    Ensures the session is closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
