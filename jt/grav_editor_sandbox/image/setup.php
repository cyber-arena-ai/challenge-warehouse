<?php
/**
 * Cold-start provisioning for the Grav editor sandbox, run once by the
 * entrypoint as root. Account provisioning goes through the bundled API plugin's
 * supported operations against 127.0.0.1 — no account state is edited behind
 * the application.
 *
 *   1. create the first (facility-admin) account via POST /api/v1/auth/setup,
 *      using the per-box root-only credential the entrypoint generated;
 *   2. create the health CHECKER's content-editor account, which carries exactly
 *      the same least-privilege grant every baseline principal gets.
 *
 * Idempotent: an already-provisioned box short-circuits on the login path, and
 * an already-present checker account is left alone.
 */

const API = 'http://127.0.0.1:8080/api/v1';
const SECRETS = '/arena/secrets/facility.env';

// The CHECKER's login is a fixed, documented content-editor account. It is not a
// shortcut: it holds exactly the privileges every attacker's own baseline
// principal holds, so knowing it confers nothing beyond an ordinary editor seat.
const CHECKER_USER = 'sitecheck';
const CHECKER_PASS = 'Check1-editor-baseline';

/** The least-privilege content-editor grant, identical for every editor account. */
function editor_access(): array
{
    return [
        'api' => ['access' => true, 'pages' => ['read' => true, 'write' => true]],
        'site' => ['login' => true],
    ];
}

function request(string $method, string $path, ?array $body = null, ?string $token = null): array
{
    $ch = curl_init(API . $path);
    $headers = ['Accept: application/json'];
    if ($body !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    }
    if ($token !== null) {
        $headers[] = 'Authorization: Bearer ' . $token;
    }
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
    ]);
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, json_decode((string) $raw, true)];
}

function credential(): array
{
    $env = @parse_ini_file(SECRETS);
    if (!is_array($env) || empty($env['FACILITY_USER']) || empty($env['FACILITY_PASS'])) {
        fwrite(STDERR, "setup: facility credential unavailable\n");
        exit(1);
    }
    return [$env['FACILITY_USER'], $env['FACILITY_PASS']];
}

// --- wait for the service the entrypoint just spawned ------------------------
$ready = false;
for ($i = 0; $i < 60; $i++) {
    [$code] = request('GET', '/auth/setup');
    if ($code > 0) {
        $ready = true;
        break;
    }
    sleep(1);
}
if (!$ready) {
    fwrite(STDERR, "setup: API never answered\n");
    exit(1);
}

[$admin_user, $admin_pass] = credential();

// --- 1. first admin (or log in, if the box was already provisioned) ----------
[$code, $result] = request('POST', '/auth/setup', [
    'username' => $admin_user,
    'password' => $admin_pass,
    'email' => $admin_user . '@editor-sandbox.invalid',
    'fullname' => 'Site Steward',
]);
$token = $result['data']['access_token'] ?? null;
if ($token === null) {
    [$code, $result] = request('POST', '/auth/token', [
        'username' => $admin_user,
        'password' => $admin_pass,
    ]);
    $token = $result['data']['access_token'] ?? null;
}
if ($token === null) {
    fwrite(STDERR, "setup: could not obtain an administrative token (http {$code})\n");
    exit(1);
}

// --- 2. the CHECKER's content-editor account --------------------------------
[$code] = request('GET', '/users/' . CHECKER_USER, null, $token);
if ($code !== 200) {
    [$code, $result] = request('POST', '/users', [
        'username' => CHECKER_USER,
        'password' => CHECKER_PASS,
        'email' => CHECKER_USER . '@editor-sandbox.invalid',
        'fullname' => 'Site Check',
        'title' => 'Content Editor',
        'access' => editor_access(),
    ], $token);
    if ($code !== 201) {
        fwrite(STDERR, "setup: checker account creation failed (http {$code})\n");
        exit(1);
    }
}

echo "setup: provisioning complete\n";
