#!/usr/bin/env php
<?php
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

declare(strict_types=1);

define('MINIVAULT_EXT', '.enc');
define('STATE_EXT',     '.mvstate');

// ── Crypto ────────────────────────────────────

function derive_key(string $password): string
{
    return hash('sha256', $password, true); // raw binary, 32 bytes
}

function mv_encrypt(string $plaintext, string $password): string
{
    $key       = derive_key($password);
    $iv        = random_bytes(16);
    $integrity = hash('sha256', $plaintext, true); // 32 bytes

    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($ciphertext === false) {
        throw new \RuntimeException('openssl_encrypt falló: ' . openssl_error_string());
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

    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($plaintext === false) {
        throw new \RuntimeException('Contraseña incorrecta o archivo corrupto.');
    }

    $computed = hash('sha256', $plaintext, true);
    if (!hash_equals($computed, $integrity)) {
        throw new \RuntimeException('Fallo de integridad: la contraseña es incorrecta o el archivo fue modificado.');
    }

    return $plaintext;
}

// ── State ─────────────────────────────────────

function state_path(string $enc_path): string
{
    return $enc_path . STATE_EXT;
}

function save_state(string $enc_path, string $tmp_path, string $hash): void
{
    file_put_contents(
        state_path($enc_path),
        json_encode(['enc' => $enc_path, 'tmp' => $tmp_path, 'hash' => $hash])
    );
}

function load_state(string $enc_path): ?array
{
    $sp = state_path($enc_path);
    if (!file_exists($sp)) return null;
    return json_decode(file_get_contents($sp), true);
}

function delete_state(string $enc_path): void
{
    $sp = state_path($enc_path);
    if (file_exists($sp)) unlink($sp);
}

function file_hash_mv(string $path): string
{
    return hash_file('sha256', $path);
}

function secure_delete(string $path): void
{
    if (!file_exists($path)) return;
    $size = filesize($path);
    $fh   = fopen($path, 'r+b');
    if ($fh) {
        fwrite($fh, str_repeat("\x00", $size));
        fflush($fh);
        fclose($fh);
    }
    unlink($path);
}

// ── Helpers ───────────────────────────────────

function find_env_files(string $dir = '.'): array
{
    $found = [];
    foreach (scandir($dir) as $f) {
        if ($f === '.env' || (str_ends_with($f, '.env') && $f !== '.' && $f !== '..')) {
            $found[] = $dir . DIRECTORY_SEPARATOR . $f;
        }
    }
    return $found;
}

function find_enc_files(string $dir = '.'): array
{
    $found = [];
    foreach (scandir($dir) as $f) {
        if (str_ends_with($f, MINIVAULT_EXT)) {
            $found[] = $dir . DIRECTORY_SEPARATOR . $f;
        }
    }
    return $found;
}

function select_file(array $files, string $label): string
{
    if (count($files) === 1) {
        echo "  Usando: {$files[0]}\n";
        return $files[0];
    }
    echo "\n  Se encontraron múltiples archivos {$label}:\n";
    foreach ($files as $i => $f) {
        echo "  [" . ($i + 1) . "] {$f}\n";
    }
    while (true) {
        $choice = trim(fgets(STDIN));
        if (ctype_digit($choice) && (int)$choice >= 1 && (int)$choice <= count($files)) {
            return $files[(int)$choice - 1];
        }
        echo "  Opción inválida.\n";
    }
}

function ask_password(bool $confirm = false): string
{
    while (true) {
        // Try to hide input on Unix
        if (DIRECTORY_SEPARATOR === '/') {
            system('stty -echo');
        }
        echo '  Contraseña: ';
        $pwd = trim(fgets(STDIN));
        if (DIRECTORY_SEPARATOR === '/') {
            system('stty echo');
            echo "\n";
        }
        if ($pwd === '') {
            echo "  La contraseña no puede estar vacía.\n";
            continue;
        }
        if (!$confirm) return $pwd;

        if (DIRECTORY_SEPARATOR === '/') system('stty -echo');
        echo '  Confirmar contraseña: ';
        $pwd2 = trim(fgets(STDIN));
        if (DIRECTORY_SEPARATOR === '/') {
            system('stty echo');
            echo "\n";
        }
        if ($pwd !== $pwd2) {
            echo "  Las contraseñas no coinciden.\n";
            continue;
        }
        return $pwd;
    }
}

// ── Commands ──────────────────────────────────

function cmd_create(array $args): void
{
    echo "\n🔒 MiniVault — Modo CREACIÓN\n\n";

    if (!empty($args[0])) {
        $src = $args[0];
        if (!file_exists($src)) {
            echo "  Error: no existe '{$src}'\n";
            exit(1);
        }
    } else {
        $files = find_env_files();
        if (empty($files)) {
            echo "  No se encontró ningún archivo .env en el directorio actual.\n";
            exit(1);
        }
        $src = select_file($files, '.env');
    }

    $stem = preg_replace('/^\./', '', pathinfo($src, PATHINFO_FILENAME));
    $dest = $args[1] ?? ($stem . MINIVAULT_EXT);

    $password  = ask_password(confirm: true);
    $plaintext = file_get_contents($src);
    $wire      = mv_encrypt($plaintext, $password);
    file_put_contents($dest, $wire);
    echo "\n  ✅ Archivo cifrado guardado en: {$dest}\n";
}

function cmd_open(array $args): void
{
    echo "\n🔓 MiniVault — Modo APERTURA\n\n";

    if (!empty($args[0])) {
        $enc_path = $args[0];
        if (!file_exists($enc_path)) {
            echo "  Error: no existe '{$enc_path}'\n";
            exit(1);
        }
    } else {
        $files = find_enc_files();
        if (empty($files)) {
            echo "  No se encontró ningún archivo " . MINIVAULT_EXT . " en el directorio actual.\n";
            exit(1);
        }
        $enc_path = select_file($files, MINIVAULT_EXT);
    }

    $stem     = basename($enc_path, MINIVAULT_EXT);
    $tmp_path = dirname($enc_path) . DIRECTORY_SEPARATOR . $stem . '.env';

    $password = ask_password(confirm: false);
    $wire     = trim(file_get_contents($enc_path));

    try {
        $plaintext = mv_decrypt($wire, $password);
    } catch (\RuntimeException $e) {
        echo "\n  ❌ " . $e->getMessage() . "\n";
        exit(1);
    }

    file_put_contents($tmp_path, $plaintext);
    $initial_hash = file_hash_mv($tmp_path);
    save_state($enc_path, $tmp_path, $initial_hash);

    echo "\n  ✅ Archivo temporal: {$tmp_path}\n";
    echo "  Editá el archivo. Cuando termines, presioná Enter para cerrar la sesión.\n";
    echo "  (Ctrl+C también cierra de forma segura)\n\n";

    // Cleanup function
    $close_session = function () use ($enc_path, $tmp_path, $initial_hash, $password): void {
        echo "\n  Cerrando sesión...\n";
        if (!file_exists($tmp_path)) {
            echo "  El archivo temporal ya no existe.\n";
            delete_state($enc_path);
            return;
        }
        $current_hash = file_hash_mv($tmp_path);
        if ($current_hash !== $initial_hash) {
            echo "  Se detectaron cambios. Actualizando archivo cifrado...\n";
            $new_content = file_get_contents($tmp_path);
            $new_wire    = mv_encrypt($new_content, $password);
            file_put_contents($enc_path, $new_wire);
            echo "  ✅ {$enc_path} actualizado.\n";
        } else {
            echo "  Sin cambios. El archivo cifrado no fue modificado.\n";
        }
        secure_delete($tmp_path);
        delete_state($enc_path);
        echo "  🗑️  Archivo temporal eliminado. Exposición: 0.\n";
    };

    // Register signal handlers
    if (function_exists('pcntl_signal')) {
        pcntl_signal(SIGINT,  function () use ($close_session) { $close_session(); exit(0); });
        pcntl_signal(SIGTERM, function () use ($close_session) { $close_session(); exit(0); });
        pcntl_async_signals(true);
    }

    fgets(STDIN); // Wait for Enter
    $close_session();
}

// ── Main ──────────────────────────────────────

$usage = <<<EOT

MiniVault v1.0.0 — Gestor seguro de secretos .env

Uso:
  php minivault.php create [archivo.env] [destino.enc]
  php minivault.php open   [archivo.enc]

Comandos:
  create    Cifra un archivo .env → genera un .enc
  open      Descifra temporalmente un .enc para edición

Sin argumentos de archivo, escanea el directorio actual automáticamente.

EOT;

$command = $argv[1] ?? null;
$rest    = array_slice($argv, 2);

if (!$command || $command === '-h' || $command === '--help') {
    echo $usage;
    exit(0);
}

match ($command) {
    'create' => cmd_create($rest),
    'open'   => cmd_open($rest),
    default  => (function () use ($command, $usage) {
        echo "  Comando desconocido: '{$command}'\n" . $usage;
        exit(1);
    })(),
};
