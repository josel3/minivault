#!/usr/bin/env python3
"""
MiniVault Unit Test — Python
Tests the crypto primitives directly (no interactive prompts).
Exit code 0 = pass, 1 = fail.
"""

import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from minivault import encrypt, decrypt, derive_key

PASSWORD = os.environ.get("TEST_PASSWORD", "test_password_123")
CONTENT  = os.environ.get("TEST_CONTENT", "DB_HOST=localhost\nAPI_KEY=secret\n")


def test_encrypt_decrypt_roundtrip():
    wire = encrypt(CONTENT, PASSWORD)
    assert wire, "encrypt returned empty"
    result = decrypt(wire, PASSWORD)
    assert result == CONTENT, f"Roundtrip mismatch.\nExpected: {CONTENT!r}\nGot:      {result!r}"
    print("  ✅ Roundtrip OK")


def test_wrong_password_fails():
    wire = encrypt(CONTENT, PASSWORD)
    try:
        decrypt(wire, "wrong_password")
        print("  ❌ Wrong password should have raised an error!")
        sys.exit(1)
    except (ValueError, Exception):
        print("  ✅ Wrong password correctly rejected")


def test_tampered_ciphertext_fails():
    import base64
    wire = encrypt(CONTENT, PASSWORD)
    raw  = bytearray(base64.b64decode(wire))
    # Flip a byte in the ciphertext region
    raw[-5] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode()
    try:
        decrypt(tampered, PASSWORD)
        print("  ❌ Tampered ciphertext should have failed integrity check!")
        sys.exit(1)
    except (ValueError, Exception):
        print("  ✅ Tampered ciphertext correctly rejected")


def test_output_is_base64():
    import base64
    wire = encrypt(CONTENT, PASSWORD)
    try:
        base64.b64decode(wire, validate=True)
        print("  ✅ Output is valid base64")
    except Exception:
        print("  ❌ Output is not valid base64")
        sys.exit(1)


def test_key_derivation():
    key = derive_key(PASSWORD)
    assert len(key) == 32, f"Key length should be 32, got {len(key)}"
    expected = hashlib.sha256(PASSWORD.encode()).digest()
    assert key == expected, "Key derivation mismatch"
    print("  ✅ Key derivation (SHA-256, 32 bytes) OK")


def test_unique_ciphertexts():
    wire1 = encrypt(CONTENT, PASSWORD)
    wire2 = encrypt(CONTENT, PASSWORD)
    assert wire1 != wire2, "Encrypting same data twice should produce different ciphertexts (random IV)"
    print("  ✅ Unique ciphertexts (random IV) OK")


if __name__ == "__main__":
    print("\n🧪 Python Unit Tests\n")
    test_key_derivation()
    test_encrypt_decrypt_roundtrip()
    test_wrong_password_fails()
    test_tampered_ciphertext_fails()
    test_output_is_base64()
    test_unique_ciphertexts()
    print("\n  All Python unit tests passed ✅\n")
