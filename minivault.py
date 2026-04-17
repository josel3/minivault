#!/usr/bin/env python3
"""
MiniVault - Encrypted .env secret manager
Version: 1.0.0
"""

import sys
import os
import hashlib
import base64
import json
import signal
import getpass
import glob
import struct
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    USE_CRYPTOGRAPHY = True
except ImportError:
    USE_CRYPTOGRAPHY = False

# Fallback: use subprocess with openssl binary
import subprocess

# ──────────────────────────────────────────────
# Crypto Standard (matches PHP & Node versions)
#   Algorithm : AES-256-CBC
#   Key derivation : SHA-256  (32 bytes)
#   IV : 16 random bytes
#   Integrity : SHA-256 of plaintext (32 bytes)
#   Wire format : base64( IV[16] + INTEGRITY[32] + CIPHERTEXT )
# ──────────────────────────────────────────────

MINIVAULT_EXT = ".enc"
STATE_EXT = ".mvstate"


def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt(plaintext: str, password: str) -> str:
    key = derive_key(password)
    iv = os.urandom(16)
    integrity = hashlib.sha256(plaintext.encode("utf-8")).digest()  # 32 bytes
    data = plaintext.encode("utf-8")

    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    if USE_CRYPTOGRAPHY:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
    else:
        ciphertext = _openssl_encrypt(key, iv, data)

    wire = base64.b64encode(iv + integrity + ciphertext).decode("ascii")
    return wire


def decrypt(wire: str, password: str) -> str:
    raw = base64.b64decode(wire)
    if len(raw) < 48:
        raise ValueError("Archivo cifrado corrupto o demasiado corto.")
    iv = raw[:16]
    integrity = raw[16:48]
    ciphertext = raw[48:]
    key = derive_key(password)

    if USE_CRYPTOGRAPHY:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    else:
        padded = _openssl_decrypt(key, iv, ciphertext)

    # Remove PKCS7 padding
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Contraseña incorrecta o archivo corrupto.")
    plaintext_bytes = padded[:-pad_len]

    # Verify integrity
    computed = hashlib.sha256(plaintext_bytes).digest()
    if computed != integrity:
        raise ValueError("Fallo de integridad: la contraseña es incorrecta o el archivo fue modificado.")

    return plaintext_bytes.decode("utf-8")


# ── OpenSSL subprocess fallback ────────────────

def _openssl_encrypt(key: bytes, iv: bytes, padded_data: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-nopad",
         "-K", key.hex(), "-iv", iv.hex()],
        input=padded_data, capture_output=True
    )
    if proc.returncode != 0:
        raise RuntimeError("openssl enc falló: " + proc.stderr.decode())
    return proc.stdout


def _openssl_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-nosalt", "-nopad",
         "-K", key.hex(), "-iv", iv.hex()],
        input=ciphertext, capture_output=True
    )
    if proc.returncode != 0:
        raise RuntimeError("openssl dec falló: " + proc.stderr.decode())
    return proc.stdout


# ── State file ─────────────────────────────────

def _state_path(enc_path: str) -> str:
    return enc_path + STATE_EXT


def _save_state(enc_path: str, tmp_path: str, content_hash: str):
    state = {"enc": enc_path, "tmp": tmp_path, "hash": content_hash}
    with open(_state_path(enc_path), "w") as f:
        json.dump(state, f)


def _load_state(enc_path: str):
    sp = _state_path(enc_path)
    if not os.path.exists(sp):
        return None
    with open(sp) as f:
        return json.load(f)


def _delete_state(enc_path: str):
    sp = _state_path(enc_path)
    if os.path.exists(sp):
        os.remove(sp)


def _file_hash(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _secure_delete(path: str):
    """Overwrite with zeros before unlinking."""
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    os.remove(path)


# ── File selection helpers ──────────────────────

def _find_env_files(directory: str = ".") -> list:
    return glob.glob(os.path.join(directory, "*.env")) + glob.glob(os.path.join(directory, ".env"))


def _find_enc_files(directory: str = ".") -> list:
    return glob.glob(os.path.join(directory, f"*{MINIVAULT_EXT}"))


def _select_file(files: list, label: str) -> str:
    if len(files) == 1:
        print(f"  Usando: {files[0]}")
        return files[0]
    print(f"\n  Se encontraron múltiples archivos {label}:")
    for i, f in enumerate(files):
        print(f"  [{i + 1}] {f}")
    while True:
        choice = input("  Seleccioná un número: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        print("  Opción inválida.")


def _ask_password(confirm: bool = False) -> str:
    while True:
        pwd = getpass.getpass("  Contraseña: ")
        if not pwd:
            print("  La contraseña no puede estar vacía.")
            continue
        if confirm:
            pwd2 = getpass.getpass("  Confirmar contraseña: ")
            if pwd != pwd2:
                print("  Las contraseñas no coinciden.")
                continue
        return pwd


# ── Commands ───────────────────────────────────

def cmd_create(args: list):
    """Cifra un archivo .env existente."""
    print("\n🔒 MiniVault — Modo CREACIÓN\n")

    # Determine source .env
    if args:
        src = args[0]
        if not os.path.exists(src):
            print(f"  Error: no existe '{src}'")
            sys.exit(1)
    else:
        files = _find_env_files()
        if not files:
            print("  No se encontró ningún archivo .env en el directorio actual.")
            sys.exit(1)
        src = _select_file(files, ".env")

    # Determine destination
    stem = Path(src).stem if not src.endswith(".env") else Path(src).name
    dest = stem.lstrip(".") + MINIVAULT_EXT
    if args and len(args) > 1:
        dest = args[1]

    password = _ask_password(confirm=True)

    with open(src, "r", encoding="utf-8") as f:
        plaintext = f.read()

    wire = encrypt(plaintext, password)
    with open(dest, "w") as f:
        f.write(wire)

    print(f"\n  ✅ Archivo cifrado guardado en: {dest}")


def cmd_open(args: list):
    """Descifra temporalmente un archivo .enc para edición."""
    print("\n🔓 MiniVault — Modo APERTURA\n")

    # Determine source .enc
    if args:
        enc_path = args[0]
        if not os.path.exists(enc_path):
            print(f"  Error: no existe '{enc_path}'")
            sys.exit(1)
    else:
        files = _find_enc_files()
        if not files:
            print(f"  No se encontró ningún archivo {MINIVAULT_EXT} en el directorio actual.")
            sys.exit(1)
        enc_path = _select_file(files, MINIVAULT_EXT)

    # Determine temp .env path
    stem = Path(enc_path).stem
    tmp_path = stem + ".env"

    password = _ask_password(confirm=False)

    # Read and decrypt
    with open(enc_path, "r") as f:
        wire = f.read().strip()

    try:
        plaintext = decrypt(wire, password)
    except ValueError as e:
        print(f"\n  ❌ {e}")
        sys.exit(1)

    # Write temp file
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(plaintext)

    initial_hash = _file_hash(tmp_path)
    _save_state(enc_path, tmp_path, initial_hash)

    print(f"\n  ✅ Archivo temporal: {tmp_path}")
    print("  Editá el archivo. Cuando termines, presioná Enter para cerrar la sesión.")
    print("  (Ctrl+C también cierra de forma segura)\n")

    # Register cleanup on SIGINT
    def cleanup(sig=None, frame=None):
        _close_session(enc_path, tmp_path, initial_hash, password)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    input()
    _close_session(enc_path, tmp_path, initial_hash, password)


def _close_session(enc_path: str, tmp_path: str, initial_hash: str, password: str):
    print("\n  Cerrando sesión...")

    if not os.path.exists(tmp_path):
        print("  El archivo temporal ya no existe.")
        _delete_state(enc_path)
        return

    current_hash = _file_hash(tmp_path)

    if current_hash != initial_hash:
        print("  Se detectaron cambios. Actualizando archivo cifrado...")
        with open(tmp_path, "r", encoding="utf-8") as f:
            new_content = f.read()
        wire = encrypt(new_content, password)
        with open(enc_path, "w") as f:
            f.write(wire)
        print(f"  ✅ {enc_path} actualizado.")
    else:
        print("  Sin cambios. El archivo cifrado no fue modificado.")

    _secure_delete(tmp_path)
    _delete_state(enc_path)
    print(f"  🗑️  Archivo temporal eliminado. Exposición: 0.")


# ── Entry point ────────────────────────────────

USAGE = """
MiniVault v1.0.0 — Gestor seguro de secretos .env

Uso:
  python minivault.py create [archivo.env] [destino.enc]
  python minivault.py open   [archivo.enc]

Comandos:
  create    Cifra un archivo .env → genera un .enc
  open      Descifra temporalmente un .enc para edición

Sin argumentos de archivo, escanea el directorio actual automáticamente.
"""


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(USAGE)
        sys.exit(0)

    command = sys.argv[1].lower()
    rest = sys.argv[2:]

    if command == "create":
        cmd_create(rest)
    elif command == "open":
        cmd_open(rest)
    else:
        print(f"  Comando desconocido: '{command}'")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()
