"""
Unit tests for the BlockchainService.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from app.services.blockchain_service import BlockchainService


class TestBlockchainService:
    """Test cases for BlockchainService."""

    @patch('app.services.blockchain_service.Web3')
    def test_init(self, mock_web3):
        """Test BlockchainService initialization."""
        mock_w3_instance = Mock()
        mock_web3.return_value = mock_w3_instance

        service = BlockchainService()

        mock_web3.assert_called_once()
        assert service.w3 == mock_w3_instance

    @patch('app.services.blockchain_service.Web3')
    def test_register_on_chain_success(self, mock_web3):
        """Test successful on-chain registration."""
        mock_w3_instance = Mock()
        mock_accounts = ['0x123', '0x456', '0x789']
        mock_w3_instance.eth.accounts = mock_accounts
        mock_tx_hash = Mock()
        mock_tx_hash.hex.return_value = "0xabcdef123456"
        mock_w3_instance.eth.send_transaction.return_value = mock_tx_hash
        mock_web3.return_value = mock_w3_instance

        service = BlockchainService()
        result = service.register_on_chain("test_data")

        assert result == {"transaction_id": "0xabcdef123456"}
        mock_w3_instance.eth.send_transaction.assert_called_once()

    @patch('app.services.blockchain_service.Web3')
    def test_register_on_chain_failure(self, mock_web3):
        """Test on-chain registration failure."""
        mock_w3_instance = Mock()
        mock_w3_instance.eth.send_transaction.side_effect = Exception("Blockchain error")
        mock_web3.return_value = mock_w3_instance

        service = BlockchainService()

        with pytest.raises(Exception, match="Failed to register on chain"):
            service.register_on_chain("test_data")

    @patch('app.services.blockchain_service.Web3')
    def test_get_on_chain_success(self, mock_web3):
        """Test successful on-chain data retrieval."""
        mock_w3_instance = Mock()
        mock_tx = {
            'hash': '0x123',
            'nonce': 1,
            'blockhash': '0x456',
            'blockNumber': 100,
            'transactionIndex': 0,
            'from': '0xabc',
            'to': '0xdef',
            'value': 1,
            'gas': 21000,
            'gasPrice': 20000000000,
            'input': '0x789',
            'v': 27,
            'r': '0x111',
            's': '0x222'
        }
        mock_w3_instance.eth.get_transaction.return_value = mock_tx
        mock_web3.return_value = mock_w3_instance

        service = BlockchainService()
        result = service.get_on_chain("0x123456")

        assert isinstance(result, dict)
        assert 'hash' in result
        mock_w3_instance.eth.get_transaction.assert_called_once_with("0x123456")

    @patch('app.services.blockchain_service.Web3')
    def test_get_on_chain_failure(self, mock_web3):
        """Test on-chain data retrieval failure."""
        mock_w3_instance = Mock()
        mock_w3_instance.eth.get_transaction.side_effect = Exception("Transaction not found")
        mock_web3.return_value = mock_w3_instance

        service = BlockchainService()

        with pytest.raises(Exception, match="Failed to get on chain data"):
            service.get_on_chain("0x123456")

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.anonymization_service.AnonymizationService.secure_anonymize')
    def test_verify_secure_immutable_register_success(self, mock_secure_anonymize, mock_web3):
        """Test successful verification of secure immutable register."""
        mock_w3_instance = Mock()
        mock_tx = Mock()
        mock_tx.input = b'0x' + b'expected_hash'  # Remove 0x prefix
        mock_w3_instance.eth.get_transaction.return_value = mock_tx
        mock_web3.return_value = mock_w3_instance

        mock_secure_anonymize.return_value = {"content": "expected_hash"}

        service = BlockchainService()
        result = service.verify_secure_immutable_register(
            "0x123", "test_content", "test_salt", "SHA256"
        )

        assert result == {"result": True}
        mock_secure_anonymize.assert_called_once_with("test_content", "test_salt", "SHA256")

    @patch('app.services.blockchain_service.Web3')
    @patch('app.services.anonymization_service.AnonymizationService.secure_anonymize')
    def test_verify_secure_immutable_register_failure(self, mock_secure_anonymize, mock_web3):
        """Test failed verification of secure immutable register."""
        mock_w3_instance = Mock()
        mock_tx = Mock()
        mock_tx.input = b'0x' + b'wrong_hash'
        mock_w3_instance.eth.get_transaction.return_value = mock_tx
        mock_web3.return_value = mock_w3_instance

        mock_secure_anonymize.return_value = {"content": "expected_hash"}

        service = BlockchainService()
        result = service.verify_secure_immutable_register(
            "0x123", "test_content", "test_salt", "SHA256"
        )

        assert result == {"result": False}
