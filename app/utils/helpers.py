"""
Helper functions for the PrivacyChain application.

This module contains utility functions such as salt generation.
"""
import uuid


def generate_salt() -> str:
    """
    Generate a random salt using UUID4.

    Returns:
        str: A string representation of a UUID4.
    """
    return str(uuid.uuid4())
