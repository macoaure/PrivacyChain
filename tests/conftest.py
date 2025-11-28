"""
Shared test fixtures and configuration for the PrivacyChain test suite.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.database.connection import Base
from app.api.main import app
from app.config.settings import Settings


@pytest.fixture(scope="session")
def test_settings():
    """Test settings with in-memory SQLite database."""
    return Settings()


@pytest.fixture(scope="session")
def test_engine(test_settings):
    """Create a test database engine."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def test_db_session(test_engine):
    """Create a test database session."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestingSessionLocal()
    try:
        # Clear all tables before each test
        Base.metadata.drop_all(bind=test_engine)
        Base.metadata.create_all(bind=test_engine)
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture(scope="function")
def client():
    """Create a test client for the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sample_entity_data():
    """Sample entity data for testing."""
    return {
        "content": '{"cpf":"72815157071","exam":"HIV","datetime":"2021-09-14T19:50:47.108814","result":"POS"}'
    }


@pytest.fixture
def sample_secure_entity_data():
    """Sample secure entity data for testing."""
    return {
        "content": '{"cpf":"72815157071","exam":"HIV","datetime":"2021-09-14T19:50:47.108814","result":"POS"}',
        "salt": "4efc1400-29b8-40b7-9bd7-7fce480b39e8"
    }


@pytest.fixture
def sample_tracking_data():
    """Sample tracking data for testing."""
    return {
        "canonical_data": '{"cpf":"72815157071","exam":"HIV"}',
        "anonymized_data": "hashed_data",
        "blockchain_id": 2,
        "transaction_id": "0x1234567890abcdef",
        "salt": "test_salt",
        "hash_method": "SHA256",
        "tracking_dt": "2023-01-01T00:00:00.000000",
        "locator": "72815157071"
    }
