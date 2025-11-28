// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControl
 * @dev Contrato inteligente para controle de permissões de acesso a dados.
 * Implementa operações essenciais de permissionamento: conceder, revogar, verificar e listar acessos.
 */
contract AccessControl {

    // Proprietário do contrato (pode ser alterado para multi-owner se necessário)
    address public owner;

    // Mapeamento: dataId => owner (quem registrou o dado)
    mapping(bytes32 => address) private dataOwners;

    // Mapeamento: dataId => user => hasAccess
    mapping(bytes32 => mapping(address => bool)) private accessPermissions;

    // Mapeamento: dataId => lista de usuários com acesso
    mapping(bytes32 => address[]) private accessors;

    // Mapeamento: dataId => user => índice na lista (para remoção eficiente)
    mapping(bytes32 => mapping(address => uint256)) private accessorIndex;

    // Contador de acessos por dataId
    mapping(bytes32 => uint256) private accessorCount;

    // Eventos para auditoria
    event AccessGranted(bytes32 indexed dataId, address indexed user, address indexed granter);
    event AccessRevoked(bytes32 indexed dataId, address indexed user, address indexed revoker);
    event AccessLogged(bytes32 indexed dataId, address indexed user, uint256 timestamp);
    event DataRegistered(bytes32 indexed dataId, address indexed owner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Apenas o proprietario pode executar esta acao");
        _;
    }

    modifier onlyDataOwner(bytes32 dataId) {
        require(dataOwners[dataId] == msg.sender, "Apenas o proprietario do dado pode executar esta acao");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Registra um novo dado, definindo o proprietário.
     * @param dataId Identificador único do dado (hash do localizador ou conteúdo).
     */
    function registerData(bytes32 dataId) public {
        require(dataOwners[dataId] == address(0), "Dado ja registrado");
        dataOwners[dataId] = msg.sender;
        emit DataRegistered(dataId, msg.sender);
    }

    /**
     * @dev Concede acesso ao dado para um usuário específico.
     * @param user Endereço do usuário que receberá acesso.
     * @param dataId Identificador do dado.
     */
    function grantAccess(address user, bytes32 dataId) public onlyDataOwner(dataId) {
        require(user != address(0), "Endereco invalido");
        require(!accessPermissions[dataId][user], "Usuario ja tem acesso");

        accessPermissions[dataId][user] = true;
        accessorIndex[dataId][user] = accessorCount[dataId];
        accessors[dataId].push(user);
        accessorCount[dataId]++;

        emit AccessGranted(dataId, user, msg.sender);
    }

    /**
     * @dev Revoga acesso ao dado para um usuário específico.
     * @param user Endereço do usuário que terá acesso revogado.
     * @param dataId Identificador do dado.
     */
    function revokeAccess(address user, bytes32 dataId) public onlyDataOwner(dataId) {
        require(accessPermissions[dataId][user], "Usuario nao tem acesso");

        accessPermissions[dataId][user] = false;

        // Remover da lista (swap com último e pop)
        uint256 index = accessorIndex[dataId][user];
        uint256 lastIndex = accessorCount[dataId] - 1;
        address lastUser = accessors[dataId][lastIndex];

        accessors[dataId][index] = lastUser;
        accessorIndex[dataId][lastUser] = index;

        accessors[dataId].pop();
        accessorCount[dataId]--;

        delete accessorIndex[dataId][user];

        emit AccessRevoked(dataId, user, msg.sender);
    }

    /**
     * @dev Verifica se um usuário tem acesso ao dado.
     * @param user Endereço do usuário.
     * @param dataId Identificador do dado.
     * @return Verdadeiro se o usuário tem acesso.
     */
    function hasAccess(address user, bytes32 dataId) public view returns (bool) {
        return accessPermissions[dataId][user];
    }

    /**
     * @dev Lista todos os usuários que têm acesso ao dado.
     * @param dataId Identificador do dado.
     * @return Array de endereços com acesso.
     */
    function listAccessors(bytes32 dataId) public view returns (address[] memory) {
        return accessors[dataId];
    }

    /**
     * @dev Registra uma tentativa de acesso (para auditoria).
     * @param user Endereço do usuário que tentou acessar.
     * @param dataId Identificador do dado.
     */
    function logAccess(address user, bytes32 dataId) public {
        // Qualquer um pode chamar, mas idealmente seria chamado pelo sistema off-chain
        emit AccessLogged(dataId, user, block.timestamp);
    }

    /**
     * @dev Retorna o proprietário de um dado.
     * @param dataId Identificador do dado.
     * @return Endereço do proprietário.
     */
    function getDataOwner(bytes32 dataId) public view returns (address) {
        return dataOwners[dataId];
    }

    /**
     * @dev Retorna o número de usuários com acesso a um dado.
     * @param dataId Identificador do dado.
     * @return Número de acessos concedidos.
     */
    function getAccessorCount(bytes32 dataId) public view returns (uint256) {
        return accessorCount[dataId];
    }

    /**
     * @dev Transfere propriedade de um dado para outro endereço.
     * @param dataId Identificador do dado.
     * @param newOwner Novo proprietário.
     */
    function transferOwnership(bytes32 dataId, address newOwner) public onlyDataOwner(dataId) {
        require(newOwner != address(0), "Novo proprietario invalido");
        dataOwners[dataId] = newOwner;
    }
}
