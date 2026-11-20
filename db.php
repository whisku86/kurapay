<?php
declare(strict_types=1);

function getDB(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $host = '127.0.0.1';
        $db   = 'kurapay';
        $user = 'root'; // Default XAMPP MySQL user
        $pass = '';     // Default XAMPP MySQL password (blank)
        $dsn  = "mysql:host=$host;dbname=$db;charset=utf8mb4";

        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

function checkRateLimit(PDO $pdo, string $key, int $maxAttempts = 5, int $windowSeconds = 900): void
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM login_attempts WHERE attempt_key = ? AND attempted_at > (NOW() - INTERVAL ? SECOND)'
    );
    $stmt->execute([$key, $windowSeconds]);

    if ((int)$stmt->fetchColumn() >= $maxAttempts) {
        http_response_code(429);
        exit(json_encode(['error' => 'Too many login attempts. Try again in 15 minutes.']));
    }
}

function recordFailedLogin(PDO $pdo, string $key): void
{
    $stmt = $pdo->prepare('INSERT INTO login_attempts (attempt_key, attempted_at) VALUES (?, NOW())');
    $stmt->execute([$key]);
}