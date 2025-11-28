#!/usr/bin/env python3
"""
Proxy Re-Encryption Demonstration Script.

This script demonstrates the proxy re-encryption functionality in PrivacyChain,
showing how data can be securely shared with revocable access control.

Usage:
    python demonstrate_proxy_encryption.py
"""

import json
import time
from datetime import datetime
from app.services.proxy_encryption_service import ProxyEncryptionService


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'=' * 50}")
    print(f"{title}")
    print(f"{'=' * 50}")


def print_step(step, description):
    """Print a formatted step."""
    print(f"\n📋 Step {step}: {description}")
    print("-" * 40)


def demonstrate_proxy_encryption():
    """
    Demonstrate the complete proxy re-encryption workflow.
    """
    print("🚀 PrivacyChain Proxy Re-Encryption Demonstration")
    print("This demo shows secure data sharing with revocable access control.")

    # Sample sensitive data
    sensitive_data = json.dumps({
        "patient_id": "P-12345",
        "name": "Dr. Alice Smith",
        "research_data": "Confidential medical research findings",
        "timestamp": datetime.now().isoformat(),
        "classification": "HIGHLY_CONFIDENTIAL"
    })

    locator = "research-data-12345"

    print_section("SETUP: Generate User Key Pairs")

    # Generate key pairs for different users
    print("🔐 Generating key pairs for users...")

    alice_keys = ProxyEncryptionService.generate_key_pair()  # Data Owner
    bob_keys = ProxyEncryptionService.generate_key_pair()    # Recipient 1
    charlie_keys = ProxyEncryptionService.generate_key_pair()  # Recipient 2

    print(f"✅ Alice (Data Owner) keys generated")
    print(f"   Public Key: {alice_keys['public_key'][:50]}...")

    print(f"✅ Bob (Recipient 1) keys generated")
    print(f"   Public Key: {bob_keys['public_key'][:50]}...")

    print(f"✅ Charlie (Recipient 2) keys generated")
    print(f"   Public Key: {charlie_keys['public_key'][:50]}...")

    print_section("PHASE 1: Data Owner Encrypts Sensitive Data")

    print_step(1, "Alice encrypts her research data")

    encrypted_data = ProxyEncryptionService.encrypt_for_owner(
        sensitive_data, alice_keys["public_key"], locator
    )

    print(f"✅ Data encrypted successfully!")
    print(f"   Encryption ID: {encrypted_data['encryption_id']}")
    print(f"   Locator: {encrypted_data['locator']}")
    print(f"   Encrypted Content: {encrypted_data['encrypted_content'][:50]}...")
    print(f"   Key Hash: {encrypted_data['key_hash'][:20]}...")

    print_section("PHASE 2: Secure Data Sharing via Proxy Keys")

    print_step(2, "Alice generates proxy key for Bob (24h access)")

    proxy_key_bob = ProxyEncryptionService.generate_proxy_key(
        alice_keys["private_key"],
        bob_keys["public_key"],
        locator,
        24  # 24 hours expiration
    )

    print(f"✅ Proxy key generated for Bob!")
    print(f"   Proxy ID: {proxy_key_bob['proxy_id']}")
    print(f"   Expires: {proxy_key_bob['expires_at']}")
    print(f"   Revoked: {proxy_key_bob['is_revoked']}")

    print_step(3, "Alice generates proxy key for Charlie (48h access)")

    proxy_key_charlie = ProxyEncryptionService.generate_proxy_key(
        alice_keys["private_key"],
        charlie_keys["public_key"],
        locator,
        48  # 48 hours expiration
    )

    print(f"✅ Proxy key generated for Charlie!")
    print(f"   Proxy ID: {proxy_key_charlie['proxy_id']}")
    print(f"   Expires: {proxy_key_charlie['expires_at']}")

    print_section("PHASE 3: Data Re-encryption for Recipients")

    print_step(4, "Re-encrypt data for Bob using his proxy key")

    re_encrypted_data_bob = ProxyEncryptionService.re_encrypt_data(
        encrypted_data, proxy_key_bob
    )

    print(f"✅ Data re-encrypted for Bob!")
    print(f"   Re-encryption ID: {re_encrypted_data_bob['re_encryption_id']}")
    print(f"   Proxy ID used: {re_encrypted_data_bob['proxy_id']}")
    print(f"   Re-encrypted at: {re_encrypted_data_bob['re_encrypted_at']}")

    print_step(5, "Re-encrypt data for Charlie using his proxy key")

    re_encrypted_data_charlie = ProxyEncryptionService.re_encrypt_data(
        encrypted_data, proxy_key_charlie
    )

    print(f"✅ Data re-encrypted for Charlie!")
    print(f"   Re-encryption ID: {re_encrypted_data_charlie['re_encryption_id']}")

    print_section("PHASE 4: Recipients Access Shared Data")

    print_step(6, "Bob decrypts his shared data")

    decrypted_bob = ProxyEncryptionService.decrypt_for_recipient(
        re_encrypted_data_bob, bob_keys["private_key"]
    )

    print(f"✅ Bob successfully accessed the shared data!")
    print(f"   Decrypted at: {decrypted_bob['decrypted_at']}")
    print(f"   Content preview: {decrypted_bob['decrypted_content'][:50]}...")

    print_step(7, "Charlie decrypts his shared data")

    decrypted_charlie = ProxyEncryptionService.decrypt_for_recipient(
        re_encrypted_data_charlie, charlie_keys["private_key"]
    )

    print(f"✅ Charlie successfully accessed the shared data!")
    print(f"   Decrypted at: {decrypted_charlie['decrypted_at']}")

    print_section("PHASE 5: Immediate Access Revocation (Key Feature)")

    print_step(8, "Alice revokes Bob's access (demonstrating immediate dismissal)")

    # Show proxy key is initially valid
    validity_before = ProxyEncryptionService.verify_proxy_key_validity(proxy_key_bob)
    print(f"🔍 Bob's proxy key validity BEFORE revocation: {validity_before['valid']}")

    # Revoke Bob's proxy key
    revocation_result = ProxyEncryptionService.revoke_proxy_key(
        proxy_key_bob, alice_keys["private_key"]
    )

    print(f"✅ Bob's access revoked successfully!")
    print(f"   Revocation status: {revocation_result['revoked']}")
    print(f"   Revoked at: {proxy_key_bob.get('revoked_at', 'N/A')}")

    # Show proxy key is now invalid
    validity_after = ProxyEncryptionService.verify_proxy_key_validity(proxy_key_bob)
    print(f"🔍 Bob's proxy key validity AFTER revocation: {validity_after['valid']}")
    print(f"   Reason: {validity_after.get('reason', 'N/A')}")

    print_step(9, "Verify Bob can no longer re-encrypt data")

    try:
        # This should fail because proxy key is revoked
        ProxyEncryptionService.re_encrypt_data(encrypted_data, proxy_key_bob)
        print("❌ ERROR: Bob was still able to re-encrypt data (this shouldn't happen!)")
    except Exception as e:
        print(f"✅ Bob's access properly denied: {str(e)}")

    print_step(10, "Verify Charlie still has access")

    validity_charlie = ProxyEncryptionService.verify_proxy_key_validity(proxy_key_charlie)
    print(f"🔍 Charlie's proxy key validity: {validity_charlie['valid']}")

    if validity_charlie["valid"]:
        # Charlie should still be able to access data
        new_re_encrypted_charlie = ProxyEncryptionService.re_encrypt_data(
            encrypted_data, proxy_key_charlie
        )
        print(f"✅ Charlie can still access data (his key not revoked)")

    print_section("PHASE 6: Complete Workflow Demonstration")

    print_step(11, "Demonstrate end-to-end secure sharing")

    # Create a complete secure share for a new recipient
    dave_keys = ProxyEncryptionService.generate_key_pair()

    secure_share = ProxyEncryptionService.create_secure_share(
        sensitive_data,
        "complete-demo-locator",
        alice_keys["private_key"],
        dave_keys["public_key"],
        12  # 12 hours expiration
    )

    print(f"✅ Complete secure share created!")
    print(f"   Share ID: {secure_share['share_id']}")
    print(f"   Includes: encrypted_data, proxy_key, re_encrypted_data")

    # Dave can immediately access the shared data
    dave_decrypted = ProxyEncryptionService.decrypt_for_recipient(
        secure_share["re_encrypted_data"], dave_keys["private_key"]
    )

    print(f"✅ Dave immediately accessed shared data!")

    print_section("SUMMARY: Key Capabilities Demonstrated")

    print("🎯 This demonstration showed:")
    print("   ✅ Secure data encryption by owner")
    print("   ✅ Proxy key generation for multiple recipients")
    print("   ✅ Data re-encryption without exposing owner's private key")
    print("   ✅ Successful data access by authorized recipients")
    print("   ✅ IMMEDIATE access revocation (dismissible proxy keys)")
    print("   ✅ Selective revocation (Charlie kept access, Bob lost access)")
    print("   ✅ Complete end-to-end workflow automation")

    print("\n🔐 Security Features:")
    print("   • Owner's private key never exposed to recipients")
    print("   • Proxy keys can be revoked instantly")
    print("   • Time-based expiration for automatic access control")
    print("   • Each recipient gets unique proxy keys")
    print("   • Original data remains encrypted with owner's key")

    print("\n🚀 Use Cases:")
    print("   • Temporary data sharing in healthcare")
    print("   • Research collaboration with time limits")
    print("   • Conditional access to sensitive documents")
    print("   • Emergency access with audit trails")
    print("   • Multi-party data analysis with revocable permissions")

    print("\n" + "="*60)
    print("🎉 PROXY RE-ENCRYPTION DEMONSTRATION COMPLETED SUCCESSFULLY!")
    print("="*60)


if __name__ == "__main__":
    try:
        demonstrate_proxy_encryption()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Error during demonstration: {str(e)}")
        import traceback
        traceback.print_exc()
