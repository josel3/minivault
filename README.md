# 🔒 MiniVault

> Gestor minimalista de secretos `.env` — cifra tus secretos locales mientras no los usás.

MiniVault es un conjunto de scripts **interoperables** (Python, Node.js, PHP) que cifran archivos `.env` en un formato binario seguro `.enc`. El archivo descifrado vive **solo en memoria de sesión**: cuando cerrás la sesión, el temporal se borra de forma segura automáticamente.

No requiere instalación de dependencias. Todo usa el runtime nativo y OpenSSL del sistema.

---

## ¿Cómo funciona?

```
.env (texto plano)
    │
    │  create
    ▼
 secrets.enc  ◄──── único archivo que commiteas / compartís
    │
    │  open
    ▼
 secrets.env  (temporal, solo durante la sesión)
    │
    │  <editás, trabajás normalmente>
    │
    │  Enter / Ctrl+C
    ▼
 secrets.enc  (actualizado si hubo cambios)
 secrets.env  ELIMINADO de forma segura (sobreescrito con ceros)
```

**Exposición en reposo = 0.**

---

## Estándar criptográfico

Todos los scripts implementan exactamente el mismo estándar, lo que garantiza interoperabilidad total:

| Parámetro         | Valor                              |
|-------------------|------------------------------------|
| Algoritmo         | AES-256-CBC                        |
| Derivación de clave | SHA-256(password) → 32 bytes     |
| IV                | 16 bytes aleatorios (por cifrado)  |
| Firma de integridad | SHA-256(plaintext) → 32 bytes   |
| Formato de salida | `base64( IV[16] + SHA256[32] + Ciphertext )` |

---

## Instalación

No hay instalación. Descargá el script para tu entorno:

```bash
# Python (requiere Python 3.8+)
curl -O https://raw.githubusercontent.com/tu-usuario/minivault/main/minivault.py
chmod +x minivault.py

# Node.js (requiere Node 16+)
curl -O https://raw.githubusercontent.com/tu-usuario/minivault/main/minivault.js
chmod +x minivault.js

# PHP (requiere PHP 8.1+ con extensión openssl)
curl -O https://raw.githubusercontent.com/tu-usuario/minivault/main/minivault.php
chmod +x minivault.php
```

No se instalan dependencias externas. OpenSSL es parte del core de los tres runtimes.

---

## Uso

### Cifrar un `.env` (crear)

```bash
# Python
python minivault.py create
python minivault.py create .env secrets.enc

# Node.js
node minivault.js create
node minivault.js create .env secrets.enc

# PHP
php minivault.php create
php minivault.php create .env secrets.enc
```

Si no especificás archivos, MiniVault escanea el directorio actual. Si encuentra más de un `.env`, te presenta un menú de selección.

**Resultado:** genera `secrets.enc` (o `<nombre>.enc`). Podés commitear este archivo con seguridad.

---

### Abrir y editar secretos (open)

```bash
# Python
python minivault.py open
python minivault.py open secrets.enc

# Node.js
node minivault.js open
node minivault.js open secrets.enc

# PHP
php minivault.php open
php minivault.php open secrets.enc
```

**Flujo:**
1. MiniVault descifra el `.enc` y escribe un `.env` temporal.
2. Vos editás el archivo con cualquier editor.
3. Cuando terminás, presionás **Enter** (o **Ctrl+C**).
4. MiniVault compara el hash del archivo temporal contra el hash inicial.
   - Si **cambió**: actualiza el `.enc` con el nuevo contenido.
   - Si **no cambió**: no toca el `.enc`.
5. El `.env` temporal se sobreescribe con ceros y se elimina.

---

## Interoperabilidad

Los tres scripts son 100% interoperables. Podés cifrar con Python y descifrar con PHP, o viceversa:

```bash
# Cifra con Python
python minivault.py create .env secrets.enc

# Descifra con PHP — funciona perfectamente
php minivault.php open secrets.enc

# O con Node
node minivault.js open secrets.enc
```

---

## Agregar `.enc` al repositorio y `.env` al `.gitignore`

```gitignore
# .gitignore
.env
*.env
*.mvstate

# Esto SÍ va al repo:
# secrets.enc
```

---

## Estructura del proyecto

```
minivault/
├── minivault.py          # Script Python
├── minivault.js          # Script Node.js
├── minivault.php         # Script PHP
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions CI
├── tests/
│   ├── test_unit.py      # Unit tests Python
│   ├── test_unit.js      # Unit tests Node.js
│   ├── test_unit.php     # Unit tests PHP
│   └── test_cross.py     # Tests de interoperabilidad
└── README.md
```

---

## Tests

### Correr tests localmente

```bash
# Unit tests
python tests/test_unit.py
node   tests/test_unit.js
php    tests/test_unit.php

# Cross-language (requiere Python + Node + PHP instalados)
python tests/test_cross.py
```

### CI (GitHub Actions)

El workflow `.github/workflows/ci.yml` corre automáticamente en cada push y pull request:

1. **Unit tests** por lenguaje — cada versión cifra y descifra en su propio runtime.
2. **Cross tests** — matriz completa: cada versión cifra, las otras dos descifran.

Si cualquier test falla, el CI falla y bloquea el merge.

---

## Seguridad

- **Sin dependencias externas**: todo el código usa APIs nativas del runtime.
- **IV aleatorio por cifrado**: dos cifrados del mismo contenido producen ciphertexts distintos.
- **Firma de integridad**: SHA-256 del plaintext incluido en el wire. Detecta contraseña incorrecta y tampering.
- **Limpieza segura**: el temporal se sobreescribe con ceros antes de `unlink` (mitiga recuperación forense básica).
- **SIGINT/SIGTERM capturados**: Ctrl+C no deja el archivo temporal huérfano.
- **`hash_equals` / `timingSafeEqual`**: comparaciones de integridad resistentes a timing attacks.

---

## Requisitos

| Runtime | Versión mínima | Extensión requerida |
|---------|---------------|---------------------|
| Python  | 3.8+          | `hashlib`, `os.urandom` (stdlib) — `cryptography` opcional |
| Node.js | 16+           | `crypto` (stdlib)   |
| PHP     | 8.1+          | `openssl` (usualmente incluida) |

---

## Licencia

MIT — libre para uso personal y comercial.
