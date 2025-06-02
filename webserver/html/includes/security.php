<?php
declare(strict_types=1);

require_once __DIR__ . '/logger.php';

class SecurityHelper
{
    private const SECURITY_HEADERS = [
        "X-Content-Type-Options: nosniff", "X-Frame-Options: SAMEORIGIN", "X-XSS-Protection: 1; mode=block", "Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; connect-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';", "Referrer-Policy: strict-origin-when-cross-origin", "Permissions-Policy: geolocation=(), camera=(), microphone=(), fullscreen=*, payment=()", "Cross-Origin-Resource-Policy: same-origin", "X-Permitted-Cross-Domain-Policies: none"
    ];

    public static function initSecureSession(): void
    {
        try {
            self::setSecureCookieParams();
            self::startSession();
            self::regenerateSessionId();
            self::addSecurityHeaders();

            logDebug("Secure session initialized for IP: " . self::anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

        } catch (Exception $e) {
            logError("Secure session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 0, $e);
        }
    }

    private static function setSecureCookieParams(): void
    {
        $cookieParams = [
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ];

        if (!session_set_cookie_params($cookieParams)) {
            throw new RuntimeException('Failed to set secure session cookie parameters');
        }
    }

    private static function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE && !session_start()) {
            throw new RuntimeException('Failed to start secure session');
        }
    }

    private static function regenerateSessionId(): void
    {
        if (empty($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        }
    }

    public static function addSecurityHeaders(): void
    {
        try {
            foreach (self::SECURITY_HEADERS as $header) {
                header($header);
            }
            logDebug("Security headers added for IP: " . self::anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        } catch (Exception $e) {
            logError("Failed to add security headers: " . $e->getMessage());
        }
    }

    public static function generateCsrfToken(): string
    {
        try {
            if (empty($_SESSION)) {
                throw new RuntimeException('Session not initialized');
            }

            $token = bin2hex(random_bytes(32));
            if ($token === false) {
                throw new RuntimeException('CSRF token generation failed');
            }

            $_SESSION['csrf_token'] = $token;
            $_SESSION['csrf_token_time'] = time();

            logDebug("CSRF token generated for session ID: " . session_id());
            return $token;

        } catch (Exception $e) {
            logError("CSRF token generation failed: " . $e->getMessage());
            throw new RuntimeException('Security token error', 0, $e);
        }
    }

    public static function validateCsrfToken(string $token): bool
    {
        try {
            if (empty($_SESSION['csrf_token']) || empty($token)) {
                logError("Missing CSRF token in session or request");
                return false;
            }

            if (!self::isValidTokenFormat($token)) {
                logError("Invalid CSRF token format from IP: " . self::anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                return false;
            }

            if (self::isTokenExpired()) {
                logError("Expired CSRF token detected");
                return false;
            }

            return self::verifyToken($token);

        } catch (Exception $e) {
            logError("CSRF validation error: " . $e->getMessage());
            return false;
        }
    }

    private static function isValidTokenFormat(string $token): bool
    {
        return preg_match('/^[a-f0-9]{64}$/', $token) === 1;
    }

    private static function isTokenExpired(): bool
    {
        $tokenAge = time() - ($_SESSION['csrf_token_time'] ?? 0);
        return $tokenAge > 3600;
    }

    private static function verifyToken(string $token): bool
    {
        $isValid = hash_equals($_SESSION['csrf_token'], $token);
        if (!$isValid) {
            logError("Invalid CSRF token provided from IP: " . self::anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        }
        return $isValid;
    }

    public static function validateSession(): bool
    {
        try {
            if (!self::hasValidSessionData()) {
                logError("Session validation failed - missing user_id or authenticated flag");
                return false;
            }

            if (!self::hasConsistentSession()) {
                logError("Session validation failed - IP or User-Agent mismatch");
                return false;
            }

            return $_SESSION['authenticated'] === true;

        } catch (Exception $e) {
            logError("Session validation error: " . $e->getMessage());
            return false;
        }
    }

    private static function hasValidSessionData(): bool
    {
        return !empty($_SESSION['user_id']) && !empty($_SESSION['authenticated']);
    }

    private static function hasConsistentSession(): bool
    {
        $ipMatch = ($_SESSION['ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $agentMatch = ($_SESSION['user_agent'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $ipMatch && $agentMatch;
    }

    public static function validateAdminAccess(PDO $db): bool
    {
        try {
            if (!self::validateSession()) {
                throw new Exception('Unauthorized - Invalid session', 401);
            }

            $userId = $_SESSION['user_id'] ?? 0;
            $isAdmin = self::checkAdminStatus($db, $userId);

            if ($isAdmin === false) {
                logError("Admin check failed - user ID {$userId} not found in database");
                return false;
            }

            return (bool)$isAdmin;

        } catch (PDOException $e) {
            logError("Database error during admin validation: " . $e->getMessage());
            throw new RuntimeException('Authorization check failed', 500, $e);
        } catch (Exception $e) {
            logError("Admin validation error: " . $e->getMessage());
            throw $e;
        }
    }

    private static function checkAdminStatus(PDO $db, int $userId): bool
    {
        $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        if (!$stmt->execute([$userId])) {
            throw new RuntimeException('Database query failed');
        }
        return $stmt->fetchColumn();
    }

    public static function anonymizeIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return preg_replace('/\.\d+$/', '.xxx', $ip);
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return preg_replace('/:[^:]+$/', ':xxxx', $ip);
        }
        return 'invalid-ip';
    }
}

function init_secure_session(): void
{
    SecurityHelper::initSecureSession();
}

function add_security_headers(): void
{
    SecurityHelper::addSecurityHeaders();
}

function generate_csrf_token(): string
{
    return SecurityHelper::generateCsrfToken();
}

function validate_csrf_token(string $token): bool
{
    return SecurityHelper::validateCsrfToken($token);
}

function validate_session(): bool
{
    return SecurityHelper::validateSession();
}

function validate_admin_access(PDO $db): bool
{
    return SecurityHelper::validateAdminAccess($db);
}