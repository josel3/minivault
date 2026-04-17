#!/usr/bin/env node
/**
 * MiniVault - Encrypted .env secret manager
 * Version: 1.0.0
 *
 * Crypto Standard:
 *   Algorithm  : AES-256-CBC
 *   Key        : SHA-256(password) → 32 bytes
 *   IV         : 16 random bytes
 *   Integrity  : SHA-256(plaintext) → 32 bytes
 *   Wire format: base64( IV[16] + INTEGRITY[32] + CIPHERTEXT )
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { execSync } = require("child_process");

const MINIVAULT_EXT = ".enc";
const STATE_EXT = ".mvstate";

// ── Crypto ────────────────────────────────────

function deriveKey(password) {
  return crypto.createHash("sha256").update(password, "utf8").digest();
}

function encrypt(plaintext, password) {
  const key = deriveKey(password);
  const iv = crypto.randomBytes(16);
  const integrity = crypto.createHash("sha256").update(plaintext, "utf8").digest();

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);

  const wire = Buffer.concat([iv, integrity, encrypted]);
  return wire.toString("base64");
}

function decrypt(wire, password) {
  const raw = Buffer.from(wire, "base64");
  if (raw.length < 48) {
    throw new Error("Archivo cifrado corrupto o demasiado corto.");
  }

  const iv = raw.slice(0, 16);
  const integrity = raw.slice(16, 48);
  const ciphertext = raw.slice(48);
  const key = deriveKey(password);

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

// ── State ─────────────────────────────────────

function statePath(encPath) {
  return encPath + STATE_EXT;
}

function saveState(encPath, tmpPath, hash) {
  fs.writeFileSync(statePath(encPath), JSON.stringify({ enc: encPath, tmp: tmpPath, hash }));
}

function loadState(encPath) {
  const sp = statePath(encPath);
  if (!fs.existsSync(sp)) return null;
  return JSON.parse(fs.readFileSync(sp, "utf8"));
}

function deleteState(encPath) {
  const sp = statePath(encPath);
  if (fs.existsSync(sp)) fs.unlinkSync(sp);
}

function fileHash(filePath) {
  const data = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

function secureDelete(filePath) {
  if (!fs.existsSync(filePath)) return;
  try {
    const size = fs.statSync(filePath).size;
    const fd = fs.openSync(filePath, "r+");
    fs.writeSync(fd, Buffer.alloc(size, 0));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
  } catch (_) {}
  fs.unlinkSync(filePath);
}

// ── Helpers ───────────────────────────────────

function findEnvFiles(dir = ".") {
  return fs.readdirSync(dir)
    .filter(f => f === ".env" || f.endsWith(".env"))
    .map(f => path.join(dir, f));
}

function findEncFiles(dir = ".") {
  return fs.readdirSync(dir)
    .filter(f => f.endsWith(MINIVAULT_EXT))
    .map(f => path.join(dir, f));
}

function selectFile(files, label) {
  if (files.length === 1) {
    console.log(`  Usando: ${files[0]}`);
    return Promise.resolve(files[0]);
  }
  console.log(`\n  Se encontraron múltiples archivos ${label}:`);
  files.forEach((f, i) => console.log(`  [${i + 1}] ${f}`));
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = () => {
      rl.question("  Seleccioná un número: ", answer => {
        const n = parseInt(answer, 10);
        if (n >= 1 && n <= files.length) {
          rl.close();
          resolve(files[n - 1]);
        } else {
          console.log("  Opción inválida.");
          ask();
        }
      });
    };
    ask();
  });
}

function askPassword(confirm = false) {
  return new Promise((resolve, reject) => {
    // Use readline with muted output trick
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const readHidden = (prompt) =>
      new Promise(res => {
        process.stdout.write(prompt);
        let pwd = "";
        const stdin = process.stdin;
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding("utf8");
        const onData = (ch) => {
          if (ch === "\n" || ch === "\r" || ch === "\u0003") {
            stdin.setRawMode(false);
            stdin.pause();
            stdin.removeListener("data", onData);
            process.stdout.write("\n");
            if (ch === "\u0003") process.exit(0);
            res(pwd);
          } else if (ch === "\u007f") {
            pwd = pwd.slice(0, -1);
          } else {
            pwd += ch;
          }
        };
        stdin.on("data", onData);
      });

    rl.close();

    (async () => {
      while (true) {
        const pwd = await readHidden("  Contraseña: ");
        if (!pwd) { console.log("  La contraseña no puede estar vacía."); continue; }
        if (!confirm) { resolve(pwd); return; }
        const pwd2 = await readHidden("  Confirmar contraseña: ");
        if (pwd !== pwd2) { console.log("  Las contraseñas no coinciden."); continue; }
        resolve(pwd);
        return;
      }
    })().catch(reject);
  });
}

function askEnter() {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question("", () => { rl.close(); resolve(); });
  });
}

// ── Commands ──────────────────────────────────

async function cmdCreate(args) {
  console.log("\n🔒 MiniVault — Modo CREACIÓN\n");

  let src;
  if (args[0]) {
    src = args[0];
    if (!fs.existsSync(src)) { console.error(`  Error: no existe '${src}'`); process.exit(1); }
  } else {
    const files = findEnvFiles();
    if (!files.length) { console.error("  No se encontró ningún archivo .env en el directorio actual."); process.exit(1); }
    src = await selectFile(files, ".env");
  }

  const stem = path.basename(src).replace(/^\./, "").replace(/\.env$/, "");
  const dest = args[1] || (stem + MINIVAULT_EXT);

  const password = await askPassword(true);
  const plaintext = fs.readFileSync(src, "utf8");
  const wire = encrypt(plaintext, password);
  fs.writeFileSync(dest, wire, "utf8");
  console.log(`\n  ✅ Archivo cifrado guardado en: ${dest}`);
}

async function cmdOpen(args) {
  console.log("\n🔓 MiniVault — Modo APERTURA\n");

  let encPath;
  if (args[0]) {
    encPath = args[0];
    if (!fs.existsSync(encPath)) { console.error(`  Error: no existe '${encPath}'`); process.exit(1); }
  } else {
    const files = findEncFiles();
    if (!files.length) { console.error(`  No se encontró ningún archivo ${MINIVAULT_EXT} en el directorio actual.`); process.exit(1); }
    encPath = await selectFile(files, MINIVAULT_EXT);
  }

  const stem = path.basename(encPath, MINIVAULT_EXT);
  const tmpPath = path.join(path.dirname(encPath), stem + ".env");

  const password = await askPassword(false);

  const wire = fs.readFileSync(encPath, "utf8").trim();
  let plaintext;
  try {
    plaintext = decrypt(wire, password);
  } catch (e) {
    console.error(`\n  ❌ ${e.message}`);
    process.exit(1);
  }

  fs.writeFileSync(tmpPath, plaintext, "utf8");
  const initialHash = fileHash(tmpPath);
  saveState(encPath, tmpPath, initialHash);

  console.log(`\n  ✅ Archivo temporal: ${tmpPath}`);
  console.log("  Editá el archivo. Cuando termines, presioná Enter para cerrar la sesión.");
  console.log("  (Ctrl+C también cierra de forma segura)\n");

  const closeSession = () => {
    console.log("\n  Cerrando sesión...");
    if (!fs.existsSync(tmpPath)) {
      console.log("  El archivo temporal ya no existe.");
      deleteState(encPath);
      return;
    }
    const currentHash = fileHash(tmpPath);
    if (currentHash !== initialHash) {
      console.log("  Se detectaron cambios. Actualizando archivo cifrado...");
      const newContent = fs.readFileSync(tmpPath, "utf8");
      const newWire = encrypt(newContent, password);
      fs.writeFileSync(encPath, newWire, "utf8");
      console.log(`  ✅ ${encPath} actualizado.`);
    } else {
      console.log("  Sin cambios. El archivo cifrado no fue modificado.");
    }
    secureDelete(tmpPath);
    deleteState(encPath);
    console.log("  🗑️  Archivo temporal eliminado. Exposición: 0.");
  };

  process.on("SIGINT", () => { closeSession(); process.exit(0); });
  process.on("SIGTERM", () => { closeSession(); process.exit(0); });

  await askEnter();
  closeSession();
}

// ── Main ──────────────────────────────────────

const USAGE = `
MiniVault v1.0.0 — Gestor seguro de secretos .env

Uso:
  node minivault.js create [archivo.env] [destino.enc]
  node minivault.js open   [archivo.enc]

Comandos:
  create    Cifra un archivo .env → genera un .enc
  open      Descifra temporalmente un .enc para edición

Sin argumentos de archivo, escanea el directorio actual automáticamente.
`;

(async () => {
  const [, , command, ...rest] = process.argv;
  if (!command || command === "-h" || command === "--help") {
    console.log(USAGE);
    process.exit(0);
  }
  if (command === "create") await cmdCreate(rest);
  else if (command === "open") await cmdOpen(rest);
  else { console.error(`  Comando desconocido: '${command}'`); console.log(USAGE); process.exit(1); }
})();
