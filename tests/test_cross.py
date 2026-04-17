#!/usr/bin/env python3
"""
MiniVault Cross-Language Interoperability Tests
Verifies that ciphertexts produced by one language can be decrypted by all others.

Matrix tested:
  Python → Node.js, PHP
  Node.js → Python, PHP
  PHP     → Python, Node.js

Exit code 0 = all pass, 1 = any failure.
"""

import os
import sys
import hashlib
import base64
import subprocess

# ── Same crypto logic as the scripts ─────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    USE_CRYPTOGRAPHY = True
except ImportError:
    USE_CRYPTOGRAPHY = False


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()


def encrypt_py(plaintext: str, password: str) -> str:
    key = derive_key(password)
    iv = os.urandom(16)
    integrity = hashlib.sha256(plaintext.encode()).digest()
    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    if USE_CRYPTOGRAPHY:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
    else:
        proc = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-nopad",
             "-K", key.hex(), "-iv", iv.hex()],
            input=data, capture_output=True
        )
        ciphertext = proc.stdout
    return base64.b64encode(iv + integrity + ciphertext).decode()


def decrypt_py(wire: str, password: str) -> str:
    raw = base64.b64decode(wire)
    iv = raw[:16]
    integrity = raw[16:48]
    ciphertext = raw[48:]
    key = derive_key(password)
    if USE_CRYPTOGRAPHY:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    else:
        proc = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-nosalt", "-nopad",
             "-K", key.hex(), "-iv", iv.hex()],
            input=ciphertext, capture_output=True
        )
        padded = proc.stdout
    pad_len = padded[-1]
    plaintext_bytes = padded[:-pad_len]
    computed = hashlib.sha256(plaintext_bytes).digest()
    if computed != integrity:
        raise ValueError("Integrity check failed")
    return plaintext_bytes.decode("utf-8")


# ── Headless decrypt helpers for Node and PHP ────────────────────

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR  = os.path.dirname(TESTS_DIR)

# We write small inline scripts that take the wire from stdin and password from env


def decrypt_node(wire: str, password: str) -> str:
    script = """
const crypto = require('crypto');
function deriveKey(p){return crypto.createHash('sha256').update(p,'utf8').digest();}
function decrypt(wire,password){
  const raw=Buffer.from(wire,'base64');
  const iv=raw.slice(0,16);const integrity=raw.slice(16,48);const ct=raw.slice(48);
  const key=deriveKey(password);
  const d=crypto.createDecipheriv('aes-256-cbc',key,iv);
  const pt=Buffer.concat([d.update(ct),d.final()]).toString('utf8');
  const comp=crypto.createHash('sha256').update(pt,'utf8').digest();
  if(!crypto.timingSafeEqual(comp,integrity))throw new Error('integrity fail');
  return pt;
}
const wire=require('fs').readFileSync('/dev/stdin','utf8').trim();
const password=process.env.MV_PWD;
try{process.stdout.write(decrypt(wire,password));}catch(e){process.stderr.write(e.message);process.exit(1);}
"""
    result = subprocess.run(
        ["node", "-e", script],
        input=wire.encode(), capture_output=True,
        env={**os.environ, "MV_PWD": password}
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode())
    return result.stdout.decode()


def decrypt_php(wire: str, password: str) -> str:
    script = r"""<?php
function derive_key($p){return hash('sha256',$p,true);}
function mv_decrypt($wire,$password){
  $raw=base64_decode($wire,true);
  $iv=substr($raw,0,16);$integrity=substr($raw,16,32);$ct=substr($raw,48);
  $key=derive_key($password);
  $pt=openssl_decrypt($ct,'aes-256-cbc',$key,OPENSSL_RAW_DATA,$iv);
  if($pt===false)throw new \RuntimeException('decrypt failed');
  $comp=hash('sha256',$pt,true);
  if(!hash_equals($comp,$integrity))throw new \RuntimeException('integrity fail');
  return $pt;
}
$wire=trim(stream_get_contents(STDIN));
$password=getenv('MV_PWD');
try{echo mv_decrypt($wire,$password);}catch(\Exception $e){fwrite(STDERR,$e->getMessage());exit(1);}
"""
    result = subprocess.run(
        ["php", "-r", "eval(file_get_contents('php://stdin'));"],
        input=(script + "\n").encode(), capture_output=True,
        env={**os.environ, "MV_PWD": password},
    )
    # Use inline script via process substitution
    # Simpler: write to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".php", delete=False, mode="w") as tf:
        tf.write(script)
        tf_name = tf.name
    try:
        result = subprocess.run(
            ["php", tf_name],
            input=wire.encode(), capture_output=True,
            env={**os.environ, "MV_PWD": password}
        )
    finally:
        os.unlink(tf_name)
    if result.returncode != 0:
        raise ValueError(result.stderr.decode())
    return result.stdout.decode()


# ── Test matrix ──────────────────────────────────────────────────

PASSWORD = os.environ.get("TEST_PASSWORD", "test_password_123")
CONTENT  = os.environ.get("TEST_CONTENT", "DB_HOST=localhost\nAPI_KEY=secret\n")

LANGUAGES = {
    "Python": {"encrypt": encrypt_py,   "decrypt": decrypt_py},
    "Node":   {"encrypt": None,          "decrypt": decrypt_node},
    "PHP":    {"encrypt": None,          "decrypt": decrypt_php},
}

# Node and PHP encrypt via Python (same standard) for cross-testing
# The real cross test: Python encrypts → Node/PHP decrypt, etc.
# For "encrypt by Node/PHP" in cross test we need their encrypt too.
# We reuse the headless inline scripts pattern:


def encrypt_node(plaintext: str, password: str) -> str:
    script = """
const crypto=require('crypto');
function deriveKey(p){return crypto.createHash('sha256').update(p,'utf8').digest();}
function encrypt(pt,password){
  const key=deriveKey(password);const iv=crypto.randomBytes(16);
  const integrity=crypto.createHash('sha256').update(pt,'utf8').digest();
  const c=crypto.createCipheriv('aes-256-cbc',key,iv);
  const enc=Buffer.concat([c.update(pt,'utf8'),c.final()]);
  return Buffer.concat([iv,integrity,enc]).toString('base64');
}
const pt=require('fs').readFileSync('/dev/stdin','utf8');
process.stdout.write(encrypt(pt,process.env.MV_PWD));
"""
    result = subprocess.run(
        ["node", "-e", script],
        input=plaintext.encode(), capture_output=True,
        env={**os.environ, "MV_PWD": password}
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode())
    return result.stdout.decode()


def encrypt_php(plaintext: str, password: str) -> str:
    script = r"""<?php
function derive_key($p){return hash('sha256',$p,true);}
function mv_encrypt($pt,$password){
  $key=derive_key($password);$iv=random_bytes(16);
  $integrity=hash('sha256',$pt,true);
  $ct=openssl_encrypt($pt,'aes-256-cbc',$key,OPENSSL_RAW_DATA,$iv);
  return base64_encode($iv.$integrity.$ct);
}
$pt=stream_get_contents(STDIN);
echo mv_encrypt($pt,getenv('MV_PWD'));
"""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".php", delete=False, mode="w") as tf:
        tf.write(script)
        tf_name = tf.name
    try:
        result = subprocess.run(
            ["php", tf_name],
            input=plaintext.encode(), capture_output=True,
            env={**os.environ, "MV_PWD": password}
        )
    finally:
        os.unlink(tf_name)
    if result.returncode != 0:
        raise ValueError(result.stderr.decode())
    return result.stdout.decode()


ENCRYPTORS = {
    "Python": encrypt_py,
    "Node":   encrypt_node,
    "PHP":    encrypt_php,
}

DECRYPTORS = {
    "Python": decrypt_py,
    "Node":   decrypt_node,
    "PHP":    decrypt_php,
}

# ── Runner ────────────────────────────────────

failed = False

def run_cross_test(enc_lang: str, dec_lang: str):
    global failed
    label = f"{enc_lang} → {dec_lang}"
    try:
        wire   = ENCRYPTORS[enc_lang](CONTENT, PASSWORD)
        result = DECRYPTORS[dec_lang](wire, PASSWORD)
        if result == CONTENT:
            print(f"  ✅ {label}")
        else:
            print(f"  ❌ {label}: content mismatch")
            print(f"     Expected: {CONTENT!r}")
            print(f"     Got:      {result!r}")
            failed = True
    except Exception as e:
        print(f"  ❌ {label}: {e}")
        failed = True


if __name__ == "__main__":
    print("\n🔀 MiniVault Cross-Language Interoperability Tests\n")
    langs = list(ENCRYPTORS.keys())
    for enc in langs:
        for dec in langs:
            if enc != dec:
                run_cross_test(enc, dec)

    if failed:
        print("\n  Some cross-language tests FAILED ❌\n")
        sys.exit(1)
    else:
        print("\n  All cross-language tests passed ✅\n")
        sys.exit(0)
