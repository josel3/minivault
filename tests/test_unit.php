#!/usr/bin/env php
<?php
/**
 * MiniVault Unit Test — PHP
 * Tests crypto primitives directly (no interactive prompts).
 * Exit code 0 = pass, 1 = fail.
 */

declare(strict_types=1);

// ── Import crypto functions inline (same logic as minivault.php) ──

function derive_key(string $password): string
{
    return hash('sha256', $password, true);
}

function mv_encrypt(string $plaintext, string $password): string
{
    $key       = derive_key($password);
    $iv        = random_bytes(16);
    $integrity = hash('sha256', $plaintext, true);
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($ciphertext === false) {
        throw new \RuntimeException('openssl_encrypt failed: ' . openssl_error_string());
    }
    return base64_encode($iv . $integrity . $ciphertext);
}

function mv_decrypt(string $wire, string $password): string
{
    $raw = base64_decode($wire, true);
    if ($raw === false || strlen($raw) < 48) {
        throw new \RuntimeException('Archivo cifrado corrupto o demasiado corto.');
    }
    $iv         = substr($raw, 0, 16);
    $integrity  = substr($raw, 16, 32);
    $ciphertext = substr($raw, 48);
    $key        = derive_key($password);
    $plaintext  = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($plaintext === false) {
        throw new \RuntimeException('Contraseña incorrecta o archivo corrupto.');
    }
    $computed = hash('sha256', $plaintext, true);
    if (!hash_equals($computed, $integrity)) {
        throw new \RuntimeException('Fallo de integridad: la contraseña es incorrecta o el archivo fue modificado.');
    }
    return $plaintext;
}

// ── Tests ─────────────────────────────────────

$PASSWORD = getenv('TEST_PASSWORD') ?: 'test_password_123';
$CONTENT  = getenv('TEST_CONTENT')  ?: "DB_HOST=localhost\nAPI_KEY=secret\n";

$failed = false;

function ok(string $msg): void  { echo "  ✅ {$msg}\n"; }
function fail(string $msg): void {
    global $failed;
    echo "  ❌ FAIL: {$msg}\n";
    $failed = true;
}

function test_key_derivation(string $password): void
{
    $key      = derive_key($password);
    $expected = hash('sha256', $password, true);
    strlen($key) === 32     ? ok('Key length is 32 bytes') : fail("Key length wrong: " . strlen($key));
    $key === $expected      ? ok('Key derivation (SHA-256, 32 bytes) OK') : fail('Key derivation mismatch');
}

function test_roundtrip(string $content, string $password): void
{
    $wire   = mv_encrypt($content, $password);
    $result = mv_decrypt($wire, $password);
    $result === $content ? ok('Roundtrip OK') : fail("Roundtrip mismatch.\nExpected: {$content}\nGot: {$result}");
}

function test_wrong_password(string $content, string $password): void
{
    $wire = mv_encrypt($content, $password);
    try {
        mv_decrypt($wire, 'wrong_password');
        fail('Wrong password should have thrown an exception');
    } catch (\RuntimeException $e) {
        ok('Wrong password correctly rejected');
    }
}

function test_tampered_ciphertext(string $content, string $password): void
{
    $wire = mv_encrypt($content, $password);
    $raw  = base64_decode($wire);
    $raw[strlen($raw) - 5] = chr(ord($raw[strlen($raw) - 5]) ^ 0xFF);
    try {
        mv_decrypt(base64_encode($raw), $password);
        fail('Tampered ciphertext should have failed integrity check');
    } catch (\RuntimeException $e) {
        ok('Tampered ciphertext correctly rejected');
    }
}

function test_output_is_base64(string $content, string $password): void
{
    $wire  = mv_encrypt($content, $password);
    $check = base64_decode($wire, true);
    $check !== false ? ok('Output is valid base64') : fail('Output is not valid base64');
}

function test_unique_ciphertexts(string $content, string $password): void
{
    $w1 = mv_encrypt($content, $password);
    $w2 = mv_encrypt($content, $password);
    $w1 !== $w2 ? ok('Unique ciphertexts (random IV) OK') : fail('Encrypting same data twice should produce different ciphertexts');
}

// ── Run ───────────────────────────────────────

echo "\n🧪 PHP Unit Tests\n\n";
test_key_derivation($PASSWORD);
test_roundtrip($CONTENT, $PASSWORD);
test_wrong_password($CONTENT, $PASSWORD);
test_tampered_ciphertext($CONTENT, $PASSWORD);
test_output_is_base64($CONTENT, $PASSWORD);
test_unique_ciphertexts($CONTENT, $PASSWORD);

if ($failed) {
    echo "\n  Some PHP unit tests FAILED ❌\n\n";
    exit(1);
} else {
    echo "\n  All PHP unit tests passed ✅\n\n";
    exit(0);
}
