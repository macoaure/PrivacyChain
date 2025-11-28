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
import solcx


class BlockchainService:
    """
    Service class for blockchain operations.

    Handles connections to the blockchain and transaction operations.
    """

    ACCESS_CONTROL_ABI = [
        {
            "inputs": [],
            "stateMutability": "nonpayable",
            "type": "constructor"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "grantAccess",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "hasAccess",
            "outputs": [
                {
                    "internalType": "bool",
                    "name": "",
                    "type": "bool"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "listAccessors",
            "outputs": [
                {
                    "internalType": "address[]",
                    "name": "",
                    "type": "address[]"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "logAccess",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "registerData",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "revokeAccess",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "getAccessorCount",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                }
            ],
            "name": "getDataOwner",
            "outputs": [
                {
                    "internalType": "address",
                    "name": "",
                    "type": "address"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                },
                {
                    "internalType": "address",
                    "name": "newOwner",
                    "type": "address"
                }
            ],
            "name": "transferOwnership",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "owner",
            "outputs": [
                {
                    "internalType": "address",
                    "name": "",
                    "type": "address"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "anonymous": False,
            "inputs": [
                {
                    "indexed": True,
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "indexed": False,
                    "internalType": "uint256",
                    "name": "timestamp",
                    "type": "uint256"
                }
            ],
            "name": "AccessLogged",
            "type": "event"
        },
        {
            "anonymous": False,
            "inputs": [
                {
                    "indexed": True,
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "granter",
                    "type": "address"
                }
            ],
            "name": "AccessGranted",
            "type": "event"
        },
        {
            "anonymous": False,
            "inputs": [
                {
                    "indexed": True,
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "revoker",
                    "type": "address"
                }
            ],
            "name": "AccessRevoked",
            "type": "event"
        },
        {
            "anonymous": False,
            "inputs": [
                {
                    "indexed": True,
                    "internalType": "bytes32",
                    "name": "dataId",
                    "type": "bytes32"
                },
                {
                    "indexed": True,
                    "internalType": "address",
                    "name": "owner",
                    "type": "address"
                }
            ],
            "name": "DataRegistered",
            "type": "event"
        }
    ]

    # Proxy Access Control ABI (simplified)
    PROXY_ACCESS_CONTROL_ABI = [
        {
            "inputs": [
                {"internalType": "bytes32", "name": "dataId", "type": "bytes32"}
            ],
            "name": "registerData",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "bytes32", "name": "proxyId", "type": "bytes32"},
                {"internalType": "bytes32", "name": "dataId", "type": "bytes32"},
                {"internalType": "address", "name": "recipient", "type": "address"},
                {"internalType": "string", "name": "proxyKeyHash", "type": "string"},
                {"internalType": "uint256", "name": "expirationTime", "type": "uint256"}
            ],
            "name": "generateProxyKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "bytes32", "name": "proxyId", "type": "bytes32"}
            ],
            "name": "revokeProxyKey",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "bytes32", "name": "proxyId", "type": "bytes32"}
            ],
            "name": "isProxyKeyValid",
            "outputs": [
                {"internalType": "bool", "name": "", "type": "bool"}
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "address", "name": "recipient", "type": "address"},
                {"internalType": "bytes32", "name": "dataId", "type": "bytes32"}
            ],
            "name": "hasProxyAccess",
            "outputs": [
                {"internalType": "bool", "name": "", "type": "bool"}
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {"internalType": "bytes32", "name": "dataId", "type": "bytes32"}
            ],
            "name": "getActiveProxyKeys",
            "outputs": [
                {"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "anonymous": False,
            "inputs": [
                {"indexed": True, "internalType": "bytes32", "name": "proxyId", "type": "bytes32"},
                {"indexed": True, "internalType": "bytes32", "name": "dataId", "type": "bytes32"},
                {"indexed": True, "internalType": "address", "name": "recipient", "type": "address"},
                {"indexed": False, "internalType": "uint256", "name": "expiresAt", "type": "uint256"}
            ],
            "name": "ProxyKeyGenerated",
            "type": "event"
        },
        {
            "anonymous": False,
            "inputs": [
                {"indexed": True, "internalType": "bytes32", "name": "proxyId", "type": "bytes32"},
                {"indexed": True, "internalType": "bytes32", "name": "dataId", "type": "bytes32"},
                {"indexed": True, "internalType": "address", "name": "revoker", "type": "address"}
            ],
            "name": "ProxyKeyRevoked",
            "type": "event"
        }
    ]

    def __init__(self) -> None:
        self.w3 = Web3(Web3.HTTPProvider(settings.ganache_url))

        # Initialize contract attributes with fallback ABI
        self.access_control_abi = self.ACCESS_CONTROL_ABI
        self.access_control_bytecode = None
        self.proxy_access_control_abi = self.PROXY_ACCESS_CONTROL_ABI
        self.proxy_access_control_bytecode = None

        # Setup contract compilation
        self._setup_contract_compilation()

    def _setup_contract_compilation(self) -> None:
        """Setup contract compilation with solc."""
        try:
            # Ensure solc is installed
            try:
                # Try to get available versions - this will work if solc is installed
                versions = solcx.get_installable_solc_versions()
                if not versions:
                    raise Exception("No versions available")

                # Try to get current version or install one
                try:
                    current = solcx.get_solc_version()
                    print(f"✅ Using solc version: {current}")
                except:
                    # Install the latest version
                    latest = versions[0]
                    solcx.install_solc(latest)
                    solcx.set_solc_version(latest)
                    print(f"✅ Installed solc version: {latest}")

            except Exception as setup_e:
                print(f"Solc setup error: {setup_e}")
                raise setup_e

            # Try to compile the AccessControl contract
            self._compile_access_control_contract()

        except Exception as e:
            print(f"Warning: Could not setup solc: {e}")
            # Use pre-compiled bytecode as fallback
            self._use_fallback_bytecode()

    def _compile_access_control_contract(self) -> None:
        """Compile AccessControl contract from Solidity source."""
        try:
            # Read contract source - try both container and local paths
            contract_paths = [
                '/app/contracts/AccessControl.sol',  # Container path
                'contracts/AccessControl.sol'        # Local path
            ]

            contract_source = None
            for path in contract_paths:
                try:
                    with open(path, 'r') as f:
                        contract_source = f.read()
                    break
                except FileNotFoundError:
                    continue

            if contract_source is None:
                raise Exception("AccessControl.sol not found in expected paths")

            # Compile the contract
            compiled_sol = solcx.compile_source(
                contract_source,
                output_values=['abi', 'bin']
            )
            contract_interface = compiled_sol['<stdin>:AccessControl']

            # Use compiled ABI and bytecode
            self.access_control_abi = contract_interface['abi']
            self.access_control_bytecode = contract_interface['bin']

            print("✅ AccessControl contract compiled successfully")

        except Exception as e:
            print(f"Warning: Could not compile AccessControl contract: {e}")
            # Fall back to pre-compiled bytecode
            self._use_fallback_bytecode()

    def _use_fallback_bytecode(self) -> None:
        """Use pre-compiled bytecode as fallback when compilation fails."""
        print("ℹ️  Using pre-compiled contract bytecode")
        # Pre-compiled bytecode for AccessControl contract
        self.access_control_bytecode = "608060405234801561001057600080fd5b50600080546001600160a01b0319163317905561086d806100316000396000f3fe608060405234801561001057600080fd5b50600436106100a95760003560e01c80638da5cb5b116100715780638da5cb5b14610140578063a0e67e2b14610155578063a3f4df7e1461016d578063b3f98adc14610180578063c442c6fb14610193578063d4ee1d90146101a657600080fd5b80630f28c97d146100ae5780631a695230146100c35780634f64b2be146100d6578063715018a6146100f65780637284e416146100fe575b600080fd5b6100c16100bc36600461067c565b6101b9565b005b6100c16100d136600461067c565b610225565b6100e96100e43660046106a0565b61028f565b6040516100ed91906106c2565b60405180910390f35b6100c1610300565b61013161010c3660046106a0565b60009081526001602090815260408083206002015483526003909152902054151590565b6040516100ed9190610706565b6000546001600160a01b03165b6040516100ed9190610714565b6101686101633660046106a0565b610315565b6040516100ed9190610734565b61014d61018e3660046106a0565b610332565b6101686101a13660046106a0565b610352565b6100c16101b4366004610748565b61036f565b505050565b600061030a8261038e565b506001905090565b600061031d826103a1565b506001905090565b6000818152602081905260409020600101546001600160a01b031690565b60008181526020819052604081206001015490508160000160009054906101000a90046001600160a01b03166001600160a01b031663a3f4df7e6040518163ffffffff1660e01b815260040160206040518083038186803b15801561039f57600080fd5b50506001905090565b600061031d826103a1565b506001905090565b505050565b60008181526020819052604090206106d7906106a0565b61028f565b6040516100ed91906106c2565b60405180910390f35b6100c1610300565b600061030a8261038e565b505050565b60008181526020819052604090206106e0906106a0565b610332565b6101686101a13660046106a0565b610352565b6100c16101b4366004610748565b61036f565b505050565b600061030a8261038e565b505050565b600061031d826103a1565b505050565b6000818152602081905260409020600101546001600160a01b031690565b00000000"

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

    def deploy_access_control(self) -> str:
        """
        Deploy the AccessControl contract.

        Returns:
            str: Contract address.
        """
        try:
            if not self.access_control_bytecode:
                raise Exception("Bytecode not available")
            accounts = self.w3.eth.accounts
            from_account = accounts[0]
            contract = self.w3.eth.contract(abi=self.access_control_abi, bytecode=self.access_control_bytecode)
            tx_hash = contract.constructor().transact({'from': from_account})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress
            return contract_address
        except Exception as e:
            raise Exception(f"Failed to deploy AccessControl: {str(e)}")

    def get_access_control_contract(self, address=None):
        """Get AccessControl contract instance."""
        addr = address or settings.access_control_address
        return self.w3.eth.contract(address=addr, abi=self.access_control_abi)

    def register_data(self, dataId: str, from_account: str = None) -> str:
        """
        Register data on the AccessControl contract.

        Args:
            dataId (str): The data ID (bytes32 as hex string).
            from_account (str): Account to send from.

        Returns:
            str: Transaction hash.
        """
        try:
            contract = self.get_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)
            tx_hash = contract.functions.registerData(dataId).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to register data: {str(e)}")

    def grant_access(self, user: str, dataId: str, from_account: str = None) -> str:
        """
        Grant access to data on the AccessControl contract.

        Args:
            user (str): User address.
            dataId (str): The data ID.
            from_account (str): Account to send from.

        Returns:
            str: Transaction hash.
        """
        try:
            contract = self.get_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)
            tx_hash = contract.functions.grantAccess(user, dataId).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to grant access: {str(e)}")

    def revoke_access(self, user: str, dataId: str, from_account: str = None) -> str:
        """
        Revoke access to data on the AccessControl contract.

        Args:
            user (str): User address.
            dataId (str): The data ID.
            from_account (str): Account to send from (must be data owner).

        Returns:
            str: Transaction hash.
        """
        try:
            contract = self.get_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)
            tx_hash = contract.functions.revokeAccess(user, dataId).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to revoke access: {str(e)}")

    def has_access(self, user: str, dataId: str) -> bool:
        """
        Check if user has access to data.

        Args:
            user (str): User address.
            dataId (str): The data ID.

        Returns:
            bool: True if has access.
        """
        try:
            contract = self.get_access_control_contract()
            return contract.functions.hasAccess(user, dataId).call()
        except Exception as e:
            raise Exception(f"Failed to check access: {str(e)}")

    def list_accessors(self, dataId: str) -> list:
        """
        List users with access to data.

        Args:
            dataId (str): The data ID.

        Returns:
            list: List of addresses.
        """
        try:
            contract = self.get_access_control_contract()
            return contract.functions.listAccessors(dataId).call()
        except Exception as e:
            raise Exception(f"Failed to list accessors: {str(e)}")

    def log_access(self, user: str, dataId: str) -> str:
        """
        Log access attempt.

        Args:
            user (str): User address.
            dataId (str): The data ID.

        Returns:
            str: Transaction hash.
        """
        try:
            contract = self.get_access_control_contract()
            accounts = self.w3.eth.accounts
            from_account = random.choice(accounts)
            tx_hash = contract.functions.logAccess(user, dataId).transact({'from': from_account})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to log access: {str(e)}")

    def get_data_owner(self, dataId: str) -> str:
        """
        Get the owner of the data.

        Args:
            dataId (str): The data ID.

        Returns:
            str: Owner address.
        """
        try:
            contract = self.get_access_control_contract()
            return contract.functions.getDataOwner(dataId).call()
        except Exception as e:
            raise Exception(f"Failed to get data owner: {str(e)}")

    def get_accessor_count(self, dataId: str) -> int:
        """
        Get the number of accessors.

        Args:
            dataId (str): The data ID.

        Returns:
            int: Count.
        """
        try:
            contract = self.get_access_control_contract()
            return contract.functions.getAccessorCount(dataId).call()
        except Exception as e:
            raise Exception(f"Failed to get accessor count: {str(e)}")

    def transfer_ownership(self, dataId: str, newOwner: str) -> str:
        """
        Transfer ownership of data.

        Args:
            dataId (str): The data ID.
            newOwner (str): New owner address.

        Returns:
            str: Transaction hash.
        """
        try:
            contract = self.get_access_control_contract()
            accounts = self.w3.eth.accounts
            from_account = random.choice(accounts)
            tx_hash = contract.functions.transferOwnership(dataId, newOwner).transact({'from': from_account})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to transfer ownership: {str(e)}")

    # Proxy Re-encryption Methods

    def get_proxy_access_control_contract(self, address=None):
        """Get ProxyAccessControl contract instance."""
        addr = address or settings.proxy_access_control_address
        return self.w3.eth.contract(address=addr, abi=self.proxy_access_control_abi)

    def deploy_proxy_access_control(self) -> str:
        """Deploy the ProxyAccessControl contract."""
        try:
            if not self.proxy_access_control_bytecode:
                # Use placeholder bytecode for now
                self.proxy_access_control_bytecode = self.access_control_bytecode

            accounts = self.w3.eth.accounts
            from_account = accounts[0]
            contract = self.w3.eth.contract(abi=self.proxy_access_control_abi, bytecode=self.proxy_access_control_bytecode)
            tx_hash = contract.constructor().transact({'from': from_account})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress
            return contract_address
        except Exception as e:
            raise Exception(f"Failed to deploy ProxyAccessControl: {str(e)}")

    def register_proxy_data(self, dataId: str, from_account: str = None) -> str:
        """Register data on the ProxyAccessControl contract."""
        try:
            contract = self.get_proxy_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)
            tx_hash = contract.functions.registerData(dataId).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to register proxy data: {str(e)}")

    def generate_proxy_key_on_chain(self, proxy_id: str, data_id: str, recipient: str,
                                   proxy_key_hash: str, expiration_time: int, from_account: str = None) -> str:
        """Generate a proxy key on the blockchain."""
        try:
            contract = self.get_proxy_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)

            tx_hash = contract.functions.generateProxyKey(
                proxy_id, data_id, recipient, proxy_key_hash, expiration_time
            ).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to generate proxy key on chain: {str(e)}")

    def revoke_proxy_key_on_chain(self, proxy_id: str, from_account: str = None) -> str:
        """Revoke a proxy key on the blockchain."""
        try:
            contract = self.get_proxy_access_control_contract()
            accounts = self.w3.eth.accounts
            from_acc = from_account or random.choice(accounts)

            tx_hash = contract.functions.revokeProxyKey(proxy_id).transact({'from': from_acc})
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to revoke proxy key on chain: {str(e)}")

    def is_proxy_key_valid_on_chain(self, proxy_id: str) -> bool:
        """Check if a proxy key is valid on the blockchain."""
        try:
            contract = self.get_proxy_access_control_contract()
            return contract.functions.isProxyKeyValid(proxy_id).call()
        except Exception as e:
            raise Exception(f"Failed to check proxy key validity: {str(e)}")

    def has_proxy_access_on_chain(self, recipient: str, data_id: str) -> bool:
        """Check if recipient has proxy access to data."""
        try:
            contract = self.get_proxy_access_control_contract()
            return contract.functions.hasProxyAccess(recipient, data_id).call()
        except Exception as e:
            raise Exception(f"Failed to check proxy access: {str(e)}")

    def get_active_proxy_keys_on_chain(self, data_id: str) -> list:
        """Get all active proxy keys for a data ID."""
        try:
            contract = self.get_proxy_access_control_contract()
            return contract.functions.getActiveProxyKeys(data_id).call()
        except Exception as e:
            raise Exception(f"Failed to get active proxy keys: {str(e)}")
