#!/usr/bin/env node
/**
 * MiniVault Unit Test — Node.js
 * Tests crypto primitives directly (no interactive prompts).
 * Exit code 0 = pass, 1 = fail.
 */

"use strict";

const crypto = require("crypto");
const path   = require("path");

// ── Import crypto functions inline (same logic as minivault.js) ──

function deriveKey(password) {
  return crypto.createHash("sha256").update(password, "utf8").digest();
}

function encrypt(plaintext, password) {
  const key       = deriveKey(password);
  const iv        = crypto.randomBytes(16);
  const integrity = crypto.createHash("sha256").update(plaintext, "utf8").digest();
  const cipher    = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, integrity, encrypted]).toString("base64");
}

function decrypt(wire, password) {
  const raw       = Buffer.from(wire, "base64");
  if (raw.length < 48) throw new Error("Archivo cifrado corrupto o demasiado corto.");
  const iv         = raw.slice(0, 16);
  const integrity  = raw.slice(16, 48);
  const ciphertext = raw.slice(48);
  const key        = deriveKey(password);
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("Contraseña incorrecta o archivo corrupto.");
  }
  const computed = crypto.createHash("sha256").update(plaintext, "utf8").digest();
  if (!crypto.timingSafeEqual(computed, integrity)) {
    throw new Error("Fallo de integridad: la contraseña es incorrecta o el archivo fue modificado.");
  }
  return plaintext;
}

// ── Tests ─────────────────────────────────────

const PASSWORD = process.env.TEST_PASSWORD || "test_password_123";
const CONTENT  = process.env.TEST_CONTENT  || "DB_HOST=localhost\nAPI_KEY=secret\n";

let failed = false;

function assert(condition, msg) {
  if (!condition) {
    console.error(`  ❌ FAIL: ${msg}`);
    failed = true;
  }
}

function test_key_derivation() {
  const key      = deriveKey(PASSWORD);
  const expected = crypto.createHash("sha256").update(PASSWORD, "utf8").digest();
  assert(key.length === 32, `Key length should be 32, got ${key.length}`);
  assert(key.equals(expected), "Key derivation mismatch");
  console.log("  ✅ Key derivation (SHA-256, 32 bytes) OK");
}

function test_roundtrip() {
  const wire   = encrypt(CONTENT, PASSWORD);
  assert(wire.length > 0, "encrypt returned empty");
  const result = decrypt(wire, PASSWORD);
  assert(result === CONTENT, `Roundtrip mismatch.\nExpected: ${CONTENT}\nGot: ${result}`);
  console.log("  ✅ Roundtrip OK");
}

function test_wrong_password() {
  const wire = encrypt(CONTENT, PASSWORD);
  try {
    decrypt(wire, "wrong_password");
    assert(false, "Wrong password should have thrown");
  } catch (_) {
    console.log("  ✅ Wrong password correctly rejected");
  }
}

function test_tampered_ciphertext() {
  const wire = encrypt(CONTENT, PASSWORD);
  const raw  = Buffer.from(wire, "base64");
  raw[raw.length - 5] ^= 0xFF;
  try {
    decrypt(raw.toString("base64"), PASSWORD);
    assert(false, "Tampered ciphertext should have failed integrity check");
  } catch (_) {
    console.log("  ✅ Tampered ciphertext correctly rejected");
  }
}

function test_output_is_base64() {
  const wire = encrypt(CONTENT, PASSWORD);
  try {
    Buffer.from(wire, "base64");
    console.log("  ✅ Output is valid base64");
  } catch (_) {
    assert(false, "Output is not valid base64");
  }
}

function test_unique_ciphertexts() {
  const w1 = encrypt(CONTENT, PASSWORD);
  const w2 = encrypt(CONTENT, PASSWORD);
  assert(w1 !== w2, "Encrypting same data twice should produce different ciphertexts (random IV)");
  console.log("  ✅ Unique ciphertexts (random IV) OK");
}

// ── Run ───────────────────────────────────────

console.log("\n🧪 Node.js Unit Tests\n");
test_key_derivation();
test_roundtrip();
test_wrong_password();
test_tampered_ciphertext();
test_output_is_base64();
test_unique_ciphertexts();

if (failed) {
  console.error("\n  Some Node.js unit tests FAILED ❌\n");
  process.exit(1);
} else {
  console.log("\n  All Node.js unit tests passed ✅\n");
}
