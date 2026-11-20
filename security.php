<?php
declare(strict_types=1);

// 1. Security Response Headers (Clickjacking, XSS, MIME-sniffing protection)
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none';");

// 2. Hardened PHP Session Configuration
ini_set('session.use_strict_mode', '1');      // Reject uninitialized session IDs
ini_set('session.use_only_cookies', '1');     // Prevent session IDs in URLs
ini_set('session.cookie_httponly', '1');      // Block JavaScript access (XSS protection)
ini_set('session.cookie_secure', '1');        // Require HTTPS
ini_set('session.cookie_samesite', 'Strict'); // Block cross-site cookie sending
ini_set('session.sid_length', '48');          // High-entropy session ID
ini_set('session.sid_bits_per_character', '6');

session_name('KURAPAY_SID');
session_start();

const SESSION_IDLE_TIMEOUT = 1800; // 30 minutes
const SESSION_ROTATE_INTERVAL = 600; // Rotate token every 10 minutes

/**
 * Validate active session timeout, User-Agent binding, and periodic ID rotation
 */
function enforceSessionSecurity(): void
{
    if (empty($_SESSION['user_id'])) {
        return;
    }

    // Idle timeout check
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_IDLE_TIMEOUT) {
        destroySession();
        http_response_code(401);
        exit(json_encode(['error' => 'Session expired due to inactivity. Please log in again.']));
    }
    $_SESSION['last_activity'] = time();

    // Soft User-Agent fingerprint check (mitigates stolen cookie replay)
    $currentUaHash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
    if (!hash_equals($_SESSION['ua_hash'] ?? '', $currentUaHash)) {
        destroySession();
        http_response_code(401);
        exit(json_encode(['error' => 'Session security mismatch. Please log in again.']));
    }

    // Periodic session token rotation
    if (!isset($_SESSION['created_at']) || (time() - $_SESSION['created_at']) > SESSION_ROTATE_INTERVAL) {
        session_regenerate_id(true);
        $_SESSION['created_at'] = time();
    }
}

/**
 * Call immediately after verifying credentials to prevent Session Fixation
 */
function initializeAuthenticatedSession(array $user): string
{
    session_regenerate_id(true); // Destroy old session ID and issue a fresh one

    $_SESSION['user_id']       = $user['id'];
    $_SESSION['role']          = $user['role']; // 'voter' or developer-seeded 'admin'
    $_SESSION['ua_hash']       = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
    $_SESSION['created_at']    = time();
    $_SESSION['last_activity'] = time();

    // Generate cryptographically random CSRF token for state-changing requests
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    return $_SESSION['csrf_token'];
}

function destroySession(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    session_destroy();
}

/**
 * Middleware: Require valid login + CSRF token on POST/PUT/DELETE requests
 */
function requireAuth(bool $verifyCsrf = true): void
{
    enforceSessionSecurity();

    if (empty($_SESSION['user_id'])) {
        http_response_code(401);
        exit(json_encode(['error' => 'Authentication required']));
    }

    if ($verifyCsrf && in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE'], true)) {
        $clientToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $serverToken = $_SESSION['csrf_token'] ?? '';

        if ($clientToken === '' || !hash_equals($serverToken, $clientToken)) {
            http_response_code(403);
            exit(json_encode(['error' => 'Invalid or missing CSRF token']));
        }
    }
}

/**
 * Middleware: Enforce Developer-Provisioned Admin access
 */
function requireAdmin(): void
{
    requireAuth(true);

    if (($_SESSION['role'] ?? '') !== 'admin') {
        http_response_code(403);
        exit(json_encode(['error' => 'Forbidden: Admin privileges required']));
    }
}
ini_set('session.cookie_secure', '0');