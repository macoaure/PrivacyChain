# AI Coding Rules for PrivacyChain

1. **Single Responsibility Principle**: Each module, class, or function should have one reason to change. Separate concerns: API routing in routers, business logic in services, data access in CRUD.

2. **Layered Architecture**: Maintain API → Services → Data/Blockchain layers. Data flows via locator-keyed operations with salted hashing (SHA256 default).

3. **Locator as Key**: Use unique locator (e.g., "72815157071") in all payloads for tracking personal data.

4. **Secure Anonymization**: Use salted hashing with UUID salt and methods (MD5/SHA1/SHA256/SHA512). Call `AnonymizationService.secure_anonymize(content, salt)`.

5. **Blockchain Operations**: Interact via Web3.py with Ganache. Register with `BlockchainService.register_on_chain`, verify with `verify_secure_immutable_register`.

6. **Database Handling**: Use SQLAlchemy with PostgreSQL/SQLite. Track metadata in table: canonical/anonymized data, tx_id, salt.

7. **Payload Consistency**: Include `locator`, `content`, `salt`, `to_wallet`, `from_wallet`, `datetime` in transaction payloads.

8. **Error Management**: Raise custom exceptions from `main.py` for app errors.

9. **Import Style**: Use relative imports within app/.

10. **Testing Standards**: Achieve >80% coverage with pytest (async mode). Test APIs via Insomnia.

11. **Workflow Commands**: Develop locally with `uvicorn app.api.main:app --reload`, deploy with `docker-compose up`.

12. **Container Execution**: Execute commands inside the running app container using `docker-compose exec app <command>`, e.g., `docker-compose exec app pytest` for running tests.

Reference: `README.md` for examples, `init.sql` for schema.
