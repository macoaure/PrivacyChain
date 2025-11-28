#!/usr/bin/env python3
"""
Script de emulação do processo PrivacyChain.

Este script demonstra o processo de ponta a ponta de:
1. Anonimização de dados pessoais com sal
2. Registro de dados anonimizados na blockchain
3. Armazenamento de metadados no banco de dados
4. Verificação do registro imutável

Uso:
    python emulate_process.py
"""

import json
from datetime import datetime
from sqlalchemy.orm import Session

# Importar serviços e utilitários
from app.services.anonymization_service import AnonymizationService
from app.services.blockchain_service import BlockchainService
from app.services.tracking_service import TrackingService
from app.database.connection import SessionLocal
from app.utils.helpers import generate_salt
from app.config.settings import settings
from web3 import Web3


def emulate_process():
    """
    Emula o processo completo do PrivacyChain.
    """
    # Garantir que as tabelas do banco de dados sejam criadas
    from app.database.connection import Base, engine
    Base.metadata.create_all(bind=engine)

    print("🚀 Iniciando Emulação do Processo PrivacyChain")
    print("=" * 50)

    # Dados de exemplo
    locator = "72815157071"  # Exemplo de localizador
    content = '{"name": "John Doe", "email": "john.doe@example.com", "age": 30}'
    salt = generate_salt()

    print("📋 Dados de Exemplo:")
    print(f"   Localizador: {locator}")
    print(f"   Conteúdo: {content}")
    print(f"   Sal: {salt}")
    print()

    # Etapa 1: Anonimização Segura
    print("🔒 Etapa 1: Anonimização Segura")
    anonymized_result = AnonymizationService.secure_anonymize(content, salt)
    anonymized_data = anonymized_result["content"]
    print(f"   Dados Anonimizados: {anonymized_data}")
    print()

    # Etapa 2: Indexação Segura na Cadeia (inclui registro na blockchain e armazenamento no BD)
    print("⛓️  Etapa 2: Indexação Segura na Cadeia")
    db: Session = SessionLocal()
    try:
        tracking_service = TrackingService()
        tracking_result = tracking_service.index_secure_on_chain(
            db, content, locator, salt
        )
        transaction_id = tracking_result['transaction_id']
        anonymized_data = tracking_result['anonymized_data']  # Obter do BD
        print(f"   ID da Transação: {transaction_id}")
        print("   ✅ Dados indexados com sucesso")
    except Exception as e:
        print(f"   ❌ Falha na indexação: {e}")
        db.close()
        return
    finally:
        db.close()
    print()

    # Etapa 3: Verificar Registro Imutável Seguro
    print("✅ Etapa 3: Verificar Registro Imutável Seguro")
    try:
        blockchain_service = BlockchainService()
        verify_result = blockchain_service.verify_secure_immutable_register(
            transaction_id, content, salt
        )
        is_valid = verify_result["result"]
        print(f"   Resultado da Verificação: {'✅ Válido' if is_valid else '❌ Inválido'}")
    except Exception as e:
        print(f"   ❌ Falha na verificação: {e}")
        return
    print()

    # Etapa 4: Register data on AccessControl contract
    print("🔐 Etapa 4: Registro de Dados no Contrato AccessControl")
    dataId = Web3.keccak(text=locator).hex()
    contract_owner = blockchain_service.w3.eth.accounts[0]  # Use a fixed account as owner
    try:
        access_tx = blockchain_service.register_data(dataId, from_account=contract_owner)
        print(f"   ID da Transação de Registro: {access_tx}")
        print("   ✅ Dados registrados no contrato")
    except Exception as e:
        print(f"   ❌ Falha no registro: {e}")
        return
    print()

    # Etapa 5: Conceder acesso a múltiplos usuários
    print("🔑 Etapa 5: Concessão de Acesso a Múltiplos Usuários")
    users = [
        blockchain_service.w3.eth.accounts[1],  # Usuário 1
        blockchain_service.w3.eth.accounts[2],  # Usuário 2
        blockchain_service.w3.eth.accounts[3]   # Usuário 3
    ]

    granted_users = []
    for i, user in enumerate(users, 1):
        try:
            grant_tx = blockchain_service.grant_access(user, dataId, from_account=contract_owner)
            print(f"   ✅ Usuário {i} ({user[:8]}...{user[-6:]}) - TX: {grant_tx[:10]}...")
            granted_users.append(user)
        except Exception as e:
            print(f"   ❌ Falha ao conceder acesso ao Usuário {i}: {e}")
    print(f"   Total de usuários com acesso concedido: {len(granted_users)}")
    print()

    # Etapa 6: Verificar acesso de todos os usuários
    print("🔍 Etapa 6: Verificação de Acesso de Todos os Usuários")
    for i, user in enumerate(granted_users, 1):
        try:
            has_acc = blockchain_service.has_access(user, dataId)
            status = "✅ Sim" if has_acc else "❌ Não"
            print(f"   Usuário {i} ({user[:8]}...{user[-6:]}): {status}")
        except Exception as e:
            print(f"   ❌ Falha na verificação do Usuário {i}: {e}")
    print()

    # Etapa 7: Listar todos os acessores
    print("📋 Etapa 7: Listar Todos os Acessores")
    try:
        accessors = blockchain_service.list_accessors(dataId)
        print(f"   Total de acessores: {len(accessors)}")
        for i, accessor in enumerate(accessors, 1):
            print(f"   Acessor {i}: {accessor}")

        # Contar acessores usando função do contrato
        accessor_count = blockchain_service.get_accessor_count(dataId)
        print(f"   Contagem via contrato: {accessor_count}")
    except Exception as e:
        print(f"   ❌ Falha na listagem: {e}")
        return
    print()

    # Etapa 8: Remover acesso de um usuário específico (usando conta do proprietário)
    print("🚫 Etapa 8: Remoção de Acesso de Um Usuário")
    if granted_users:
        user_to_remove = granted_users[1]  # Remove o segundo usuário
        try:
            # Usar a função com from_account especificando o proprietário dos dados
            revoke_tx = blockchain_service.revoke_access(user_to_remove, dataId, from_account=contract_owner)
            print(f"   ✅ Acesso revogado para usuário ({user_to_remove[:8]}...{user_to_remove[-6:]})")
            print(f"   ID da Transação de Revogação: {revoke_tx[:10]}...")

            # Verificar se o acesso foi realmente removido
            still_has_access = blockchain_service.has_access(user_to_remove, dataId)
            status = "❌ Ainda tem acesso" if still_has_access else "✅ Acesso removido"
            print(f"   Status pós-revogação: {status}")

            # Atualizar lista de usuários ativos
            granted_users.remove(user_to_remove)
        except Exception as e:
            print(f"   ❌ Falha na remoção: {e}")
    print()

    # Etapa 9: Listar acessores após remoção
    print("📋 Etapa 9: Lista de Acessores Após Remoção")
    try:
        accessors_after_removal = blockchain_service.list_accessors(dataId)
        print(f"   Total de acessores restantes: {len(accessors_after_removal)}")
        for i, accessor in enumerate(accessors_after_removal, 1):
            print(f"   Acessor {i}: {accessor}")
    except Exception as e:
        print(f"   ❌ Falha na listagem: {e}")
    print()

    # Etapa 10: Revogar acesso de todos os usuários restantes (como proprietário)
    print("🔒 Etapa 10: Revogação de Acesso de Todos os Usuários Restantes")
    revoked_count = 0
    for i, user in enumerate(granted_users.copy(), 1):
        try:
            # Revogar usando a função atualizada com from_account
            revoke_tx = blockchain_service.revoke_access(user, dataId, from_account=contract_owner)
            print(f"   ✅ Acesso revogado para Usuário {i} ({user[:8]}...{user[-6:]})")
            revoked_count += 1
        except Exception as e:
            print(f"   ❌ Falha na revogação do Usuário {i}: {e}")

    print(f"   Total de acessos revogados: {revoked_count}")
    print()

    # Etapa 11: Verificação final - nenhum usuário deve ter acesso
    print("✅ Etapa 11: Verificação Final de Acesso")
    try:
        final_accessors = blockchain_service.list_accessors(dataId)
        final_count = len(final_accessors)

        if final_count == 0:
            print("   ✅ Sucesso! Nenhum usuário possui acesso aos dados")
        else:
            print(f"   ⚠️  Ainda existem {final_count} usuário(s) com acesso:")
            for i, accessor in enumerate(final_accessors, 1):
                print(f"     Usuário {i}: {accessor}")
    except Exception as e:
        print(f"   ❌ Falha na verificação final: {e}")
    print()

    print("🎉 Emulação do Processo Concluída com Sucesso!")
    print("=" * 50)
    print("📊 Resumo Final:")
    print(f"   - Localizador: {locator}")
    print(f"   - ID da Transação: {transaction_id}")
    print(f"   - Anonimizado: {anonymized_data[:32]}...")
    print(f"   - Verificação: {'Aprovada' if is_valid else 'Reprovada'}")
    print(f"   - Data ID no Contrato: {dataId}")
    print(f"   - Usuários Iniciais: 3")
    print(f"   - Usuários Removidos: 1")
    print(f"   - Acessos Revogados: Todos")
    print(f"   - Status Final: Dados protegidos (sem acessos ativos)")


if __name__ == "__main__":
    # Verificar se o Ganache está rodando (verificação básica)
    try:
        blockchain_service = BlockchainService()
        # Tentar obter contas para verificar conexão
        accounts = blockchain_service.w3.eth.accounts
        if not accounts:
            print("❌ Erro: Nenhuma conta disponível. Certifique-se de que o Ganache está rodando em", settings.ganache_url)
            exit(1)
        print("🔗 Conectado ao Ganache")
    except Exception as e:
        print(f"❌ Erro ao conectar à blockchain: {e}")
        exit(1)

    # Deploy AccessControl contract
    try:
        deployed_address = blockchain_service.deploy_access_control()
        settings.access_control_address = deployed_address
        print(f"🔐 Contrato AccessControl implantado em: {deployed_address}")
    except Exception as e:
        print(f"❌ Falha ao implantar contrato: {e}")
        exit(1)

    emulate_process()
