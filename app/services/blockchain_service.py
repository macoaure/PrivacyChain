"""
Service for blockchain operations.

This module handles interactions with the blockchain, such as registering and retrieving data.
"""
import json
import random
from typing import Dict, Any, Optional
from web3 import Web3
from hexbytes import HexBytes
from app.config.settings import settings
from app.utils.enums import CustomJSONEncoder


class BlockchainService:
    """
    Service class for blockchain operations.

    Handles connections to the blockchain and transaction operations.
    """

    def __init__(self) -> None:
        self.w3 = Web3(Web3.HTTPProvider(settings.ganache_url))

    def register_on_chain(self, content: str) -> Dict[str, str]:
        """
        Register anonymized data on the blockchain.

        Args:
            content (str): The data to register.

        Returns:
            Dict[str, str]: Dictionary with transaction ID.

        Raises:
            Exception: If registration fails.
        """
        try:
            accounts = self.w3.eth.accounts
            source = random.choice(accounts)
            target = random.choice(accounts)

            transaction_hash = self.w3.eth.send_transaction({
                'to': target,
                'from': source,
                'value': 1,
                'data': '0x' + content  # Send as hex data
            })

            return {"transaction_id": transaction_hash.hex()}
        except Exception as e:
            raise Exception(f"Failed to register on chain: {str(e)}")

    def get_on_chain(self, transaction_id: str) -> Dict[str, Any]:
        """
        Retrieve transaction data from the blockchain.

        Args:
            transaction_id (str): The transaction ID to retrieve.

        Returns:
            Dict[str, Any]: Transaction details.

        Raises:
            Exception: If retrieval fails.
        """
        try:
            tx = self.w3.eth.get_transaction(transaction_id)
            tx_dict = dict(tx)
            tx_json = json.dumps(tx_dict, cls=CustomJSONEncoder)
            return json.loads(tx_json)
        except Exception as e:
            raise Exception(f"Failed to get on chain data: {str(e)}")

    def verify_secure_immutable_register(self, transaction_id: str, content: str, salt: str, hash_method: str = "SHA256") -> Dict[str, bool]:
        """
        Verify if the data in the blockchain matches the secure anonymization.

        Args:
            transaction_id (str): Transaction ID.
            content (str): Original content.
            salt (str): Salt used.
            hash_method (str): Hash method.

        Returns:
            Dict[str, bool]: Verification result.
        """
        try:
            tx = self.w3.eth.get_transaction(transaction_id)
            # Since data was sent as '0x' + content, tx.input[2:] is the content
            if isinstance(tx.input, str):
                anonymized_in_blockchain = tx.input[2:]
            else:
                anonymized_in_blockchain = tx.input.hex()[2:]

            from app.services.anonymization_service import AnonymizationService
            result = AnonymizationService.secure_anonymize(content, salt, hash_method)
            is_valid = result["content"] == anonymized_in_blockchain

            return {"result": is_valid}
        except Exception as e:
            raise Exception(f"Failed to verify immutable register: {str(e)}")
