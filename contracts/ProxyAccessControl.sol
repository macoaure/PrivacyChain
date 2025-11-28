// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ProxyAccessControl
 * @dev Extensão do contrato AccessControl para suporte a chaves proxy.
 * Implementa gerenciamento de chaves proxy para re-criptografia, permitindo
 * que proprietários de dados concedam acesso temporário que pode ser revogado.
 */
contract ProxyAccessControl {
    // Proprietário do contrato
    address public owner;

    // Estrutura para armazenar informações de chave proxy
    struct ProxyKey {
        bytes32 proxyId;
        bytes32 dataId;
        address dataOwner;
        address recipient;
        string proxyKeyHash;
        uint256 createdAt;
        uint256 expiresAt;
        bool isRevoked;
        bool exists;
    }

    // Mapeamento: dataId => owner (quem registrou o dado)
    mapping(bytes32 => address) private dataOwners;

    // Mapeamento: dataId => user => hasAccess (controle tradicional)
    mapping(bytes32 => mapping(address => bool)) private accessPermissions;

    // Mapeamento: proxyId => ProxyKey (chaves proxy)
    mapping(bytes32 => ProxyKey) private proxyKeys;

    // Mapeamento: dataId => proxyId[] (chaves proxy por dado)
    mapping(bytes32 => bytes32[]) private dataProxyKeys;

    // Mapeamento: dataOwner => proxyId[] (chaves proxy por proprietário)
    mapping(address => bytes32[]) private ownerProxyKeys;

    // Mapeamento: recipient => proxyId[] (chaves proxy por destinatário)
    mapping(address => bytes32[]) private recipientProxyKeys;

    // Contadores
    mapping(bytes32 => uint256) private accessorCount;
    mapping(bytes32 => uint256) private proxyKeyCount;

    // Eventos para auditoria
    event DataRegistered(bytes32 indexed dataId, address indexed owner);
    event AccessGranted(
        bytes32 indexed dataId,
        address indexed user,
        address indexed granter
    );
    event AccessRevoked(
        bytes32 indexed dataId,
        address indexed user,
        address indexed revoker
    );
    event AccessLogged(
        bytes32 indexed dataId,
        address indexed user,
        uint256 timestamp
    );

    // Eventos para chaves proxy
    event ProxyKeyGenerated(
        bytes32 indexed proxyId,
        bytes32 indexed dataId,
        address indexed recipient,
        uint256 expiresAt
    );
    event ProxyKeyRevoked(
        bytes32 indexed proxyId,
        bytes32 indexed dataId,
        address indexed revoker
    );
    event ProxyKeyExpired(bytes32 indexed proxyId, bytes32 indexed dataId);
    event ProxyAccessLogged(
        bytes32 indexed proxyId,
        bytes32 indexed dataId,
        address indexed recipient,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Apenas o proprietario pode executar esta acao"
        );
        _;
    }

    modifier onlyDataOwner(bytes32 dataId) {
        require(
            dataOwners[dataId] == msg.sender,
            "Apenas o proprietario do dado pode executar esta acao"
        );
        _;
    }

    modifier validProxyKey(bytes32 proxyId) {
        ProxyKey memory proxyKey = proxyKeys[proxyId];
        require(proxyKey.exists, "Chave proxy nao existe");
        require(!proxyKey.isRevoked, "Chave proxy foi revogada");
        require(block.timestamp <= proxyKey.expiresAt, "Chave proxy expirou");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Registra um novo dado, definindo o proprietário.
     * @param dataId Identificador único do dado.
     */
    function registerData(bytes32 dataId) public {
        require(dataOwners[dataId] == address(0), "Dado ja registrado");
        dataOwners[dataId] = msg.sender;
        emit DataRegistered(dataId, msg.sender);
    }

    /**
     * @dev Gera uma nova chave proxy para um dado e destinatário.
     * @param proxyId Identificador único da chave proxy.
     * @param dataId Identificador do dado.
     * @param recipient Endereço do destinatário.
     * @param proxyKeyHash Hash da chave proxy.
     * @param expirationTime Timestamp de expiração.
     */
    function generateProxyKey(
        bytes32 proxyId,
        bytes32 dataId,
        address recipient,
        string memory proxyKeyHash,
        uint256 expirationTime
    ) public onlyDataOwner(dataId) {
        require(recipient != address(0), "Destinatario invalido");
        require(
            recipient != msg.sender,
            "Nao pode gerar chave proxy para si mesmo"
        );
        require(
            expirationTime > block.timestamp,
            "Tempo de expiracao deve ser futuro"
        );
        require(!proxyKeys[proxyId].exists, "Chave proxy ja existe");

        ProxyKey memory newProxyKey = ProxyKey({
            proxyId: proxyId,
            dataId: dataId,
            dataOwner: msg.sender,
            recipient: recipient,
            proxyKeyHash: proxyKeyHash,
            createdAt: block.timestamp,
            expiresAt: expirationTime,
            isRevoked: false,
            exists: true
        });

        proxyKeys[proxyId] = newProxyKey;
        dataProxyKeys[dataId].push(proxyId);
        ownerProxyKeys[msg.sender].push(proxyId);
        recipientProxyKeys[recipient].push(proxyId);
        proxyKeyCount[dataId]++;

        emit ProxyKeyGenerated(proxyId, dataId, recipient, expirationTime);
    }

    /**
     * @dev Revoga uma chave proxy.
     * @param proxyId Identificador da chave proxy.
     */
    function revokeProxyKey(bytes32 proxyId) public {
        ProxyKey storage proxyKey = proxyKeys[proxyId];
        require(proxyKey.exists, "Chave proxy nao existe");
        require(
            proxyKey.dataOwner == msg.sender,
            "Apenas o proprietario pode revogar"
        );
        require(!proxyKey.isRevoked, "Chave proxy ja foi revogada");

        proxyKey.isRevoked = true;
        emit ProxyKeyRevoked(proxyId, proxyKey.dataId, msg.sender);
    }

    /**
     * @dev Revoga todas as chaves proxy de um dado.
     * @param dataId Identificador do dado.
     */
    function revokeAllProxyKeys(bytes32 dataId) public onlyDataOwner(dataId) {
        bytes32[] storage proxyIds = dataProxyKeys[dataId];

        for (uint256 i = 0; i < proxyIds.length; i++) {
            ProxyKey storage proxyKey = proxyKeys[proxyIds[i]];
            if (!proxyKey.isRevoked && proxyKey.exists) {
                proxyKey.isRevoked = true;
                emit ProxyKeyRevoked(proxyIds[i], dataId, msg.sender);
            }
        }
    }

    /**
     * @dev Verifica se uma chave proxy é válida.
     * @param proxyId Identificador da chave proxy.
     * @return Verdadeiro se a chave proxy é válida.
     */
    function isProxyKeyValid(bytes32 proxyId) public view returns (bool) {
        ProxyKey memory proxyKey = proxyKeys[proxyId];
        return
            proxyKey.exists &&
            !proxyKey.isRevoked &&
            block.timestamp <= proxyKey.expiresAt;
    }

    /**
     * @dev Verifica se um destinatário tem acesso válido via chave proxy.
     * @param recipient Endereço do destinatário.
     * @param dataId Identificador do dado.
     * @return Verdadeiro se tem acesso válido via proxy.
     */
    function hasProxyAccess(
        address recipient,
        bytes32 dataId
    ) public view returns (bool) {
        bytes32[] memory proxyIds = dataProxyKeys[dataId];

        for (uint256 i = 0; i < proxyIds.length; i++) {
            ProxyKey memory proxyKey = proxyKeys[proxyIds[i]];
            if (
                proxyKey.recipient == recipient &&
                !proxyKey.isRevoked &&
                block.timestamp <= proxyKey.expiresAt
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Registra acesso via chave proxy.
     * @param proxyId Identificador da chave proxy.
     */
    function logProxyAccess(bytes32 proxyId) public validProxyKey(proxyId) {
        ProxyKey memory proxyKey = proxyKeys[proxyId];
        require(
            msg.sender == proxyKey.recipient,
            "Apenas o destinatario pode usar esta chave"
        );

        emit ProxyAccessLogged(
            proxyId,
            proxyKey.dataId,
            proxyKey.recipient,
            block.timestamp
        );
    }

    /**
     * @dev Obtém informações de uma chave proxy.
     * @param proxyId Identificador da chave proxy.
     * @return Informações da chave proxy.
     */
    function getProxyKey(
        bytes32 proxyId
    )
        public
        view
        returns (
            bytes32 dataId,
            address dataOwner,
            address recipient,
            string memory proxyKeyHash,
            uint256 createdAt,
            uint256 expiresAt,
            bool isRevoked,
            bool exists
        )
    {
        ProxyKey memory proxyKey = proxyKeys[proxyId];
        return (
            proxyKey.dataId,
            proxyKey.dataOwner,
            proxyKey.recipient,
            proxyKey.proxyKeyHash,
            proxyKey.createdAt,
            proxyKey.expiresAt,
            proxyKey.isRevoked,
            proxyKey.exists
        );
    }

    /**
     * @dev Lista todas as chaves proxy de um dado.
     * @param dataId Identificador do dado.
     * @return Array de IDs das chaves proxy.
     */
    function getDataProxyKeys(
        bytes32 dataId
    ) public view returns (bytes32[] memory) {
        return dataProxyKeys[dataId];
    }

    /**
     * @dev Lista chaves proxy ativas de um dado.
     * @param dataId Identificador do dado.
     * @return Array de IDs das chaves proxy ativas.
     */
    function getActiveProxyKeys(
        bytes32 dataId
    ) public view returns (bytes32[] memory) {
        bytes32[] memory allProxyIds = dataProxyKeys[dataId];

        // Primeiro, contar quantas chaves são ativas
        uint256 activeCount = 0;
        for (uint256 i = 0; i < allProxyIds.length; i++) {
            ProxyKey memory proxyKey = proxyKeys[allProxyIds[i]];
            if (!proxyKey.isRevoked && block.timestamp <= proxyKey.expiresAt) {
                activeCount++;
            }
        }

        // Criar array com o tamanho correto
        bytes32[] memory activeProxyIds = new bytes32[](activeCount);
        uint256 index = 0;

        for (uint256 i = 0; i < allProxyIds.length; i++) {
            ProxyKey memory proxyKey = proxyKeys[allProxyIds[i]];
            if (!proxyKey.isRevoked && block.timestamp <= proxyKey.expiresAt) {
                activeProxyIds[index] = allProxyIds[i];
                index++;
            }
        }

        return activeProxyIds;
    }

    /**
     * @dev Obtém o número de chaves proxy ativas para um dado.
     * @param dataId Identificador do dado.
     * @return Número de chaves proxy ativas.
     */
    function getActiveProxyKeyCount(
        bytes32 dataId
    ) public view returns (uint256) {
        bytes32[] memory proxyIds = dataProxyKeys[dataId];
        uint256 count = 0;

        for (uint256 i = 0; i < proxyIds.length; i++) {
            ProxyKey memory proxyKey = proxyKeys[proxyIds[i]];
            if (!proxyKey.isRevoked && block.timestamp <= proxyKey.expiresAt) {
                count++;
            }
        }
        return count;
    }

    /**
     * @dev Obtém o proprietário de um dado.
     * @param dataId Identificador do dado.
     * @return Endereço do proprietário.
     */
    function getDataOwner(bytes32 dataId) public view returns (address) {
        return dataOwners[dataId];
    }

    /**
     * @dev Transfere propriedade de um dado (revoga todas as chaves proxy).
     * @param dataId Identificador do dado.
     * @param newOwner Novo proprietário.
     */
    function transferOwnership(
        bytes32 dataId,
        address newOwner
    ) public onlyDataOwner(dataId) {
        require(newOwner != address(0), "Novo proprietario invalido");

        // Revogar todas as chaves proxy existentes
        this.revokeAllProxyKeys(dataId);

        // Transferir propriedade
        dataOwners[dataId] = newOwner;
    }

    /**
     * @dev Cleanup de chaves proxy expiradas (função utilitária).
     * @param dataId Identificador do dado.
     */
    function cleanupExpiredProxyKeys(bytes32 dataId) public {
        bytes32[] storage proxyIds = dataProxyKeys[dataId];

        for (uint256 i = 0; i < proxyIds.length; i++) {
            ProxyKey storage proxyKey = proxyKeys[proxyIds[i]];
            if (!proxyKey.isRevoked && block.timestamp > proxyKey.expiresAt) {
                emit ProxyKeyExpired(proxyIds[i], dataId);
                // Nota: Não alteramos isRevoked para distinguir entre revogação manual e expiração
            }
        }
    }
}
