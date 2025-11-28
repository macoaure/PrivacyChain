"""
Configuration settings for the PrivacyChain application.

This module handles environment variable loading and application settings.
"""
import os
from typing import Optional


class Settings:
    """
    Application settings loaded from environment variables.

    Attributes:
        database_url (str): The database connection URL.
        ganache_url (str): The URL for the Ganache Ethereum simulator.
        default_blockchain (str): The default blockchain to use.
        default_hash_method (str): The default hash method for anonymization.
    """

    def __init__(self) -> None:
        self.database_url: str = os.getenv("DATABASE_URL", "sqlite:///./privacychain.db")
        self.ganache_url: str = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
        self.default_blockchain: str = "ETHEREUM"
        self.default_hash_method: str = "SHA256"
        self.access_control_address: str = os.getenv("ACCESS_CONTROL_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")


# Global settings instance
settings = Settings()
