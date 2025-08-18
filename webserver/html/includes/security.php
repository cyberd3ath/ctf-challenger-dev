<?php
declare(strict_types=1);

require_once __DIR__ . '/logger.php';


interface ISecurityHelper
{
    public function __construct(ILogger $logger = new Logger());
    public function initSecureSession(): void;
    public function addSecurityHeaders(): void;
    public function generateCsrfToken(): string;
    public function validateCsrfToken(string $token): bool;
    public function validateSession(): bool;
    public function validateAdminAccess(PDO $db): bool;
}


class SecurityHelper implements ISecurityHelper
{    
    private const SECURITY_HEADERS = [
        "X-Content-Type-Options: nosniff", "X-Frame-Options: SAMEORIGIN", "X-XSS-Protection: 1; mode=block", "Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; connect-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';", "Referrer-Policy: strict-origin-when-cross-origin", "Permissions-Policy: geolocation=(), camera=(), microphone=(), fullscreen=*, payment=()", "Cross-Origin-Resource-Policy: same-origin", "X-Permitted-Cross-Domain-Policies: none"
    ];

    private ILogger $logger;

    public function __construct(ILogger $logger = new Logger())
    {
        $this->logger = $logger;
    }

    public function initSecureSession(): void
    {
        try {
            $this->setSecureCookieParams();
            $this->startSession();
            $this->regenerateSessionId();
            $this->addSecurityHeaders();

            $this->logger->logDebug("Secure session initialized for IP: " . $this->logger->anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));

        } catch (Exception $e) {
            $this->logger->logError("Secure session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 0, $e);
        }
    }

    private function setSecureCookieParams(): void
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

    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_NONE && !session_start()) {
            throw new RuntimeException('Failed to start secure session');
        }
    }

    private function regenerateSessionId(): void
    {
        if (empty($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        }
    }

    public function addSecurityHeaders(): void
    {
        try {
            foreach (self::SECURITY_HEADERS as $header) {
                header($header);
            }
            $this->logger->logDebug("Security headers added for IP: " . $this->logger->anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        } catch (Exception $e) {
            $this->logger->logError("Failed to add security headers: " . $e->getMessage());
        }
    }

    public function generateCsrfToken(): string
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

            $this->logger->logDebug("CSRF token generated for session ID: " . session_id());
            return $token;

        } catch (Exception $e) {
            $this->logger->logError("CSRF token generation failed: " . $e->getMessage());
            throw new RuntimeException('Security token error', 0, $e);
        }
    }

    public function validateCsrfToken(string $token): bool
    {
        try {
            if (empty($_SESSION['csrf_token']) || empty($token)) {
                $this->logger->logError("Missing CSRF token in session or request");
                return false;
            }

            if (!$this->isValidTokenFormat($token)) {
                $this->logger->logError("Invalid CSRF token format from IP: " . $this->logger->anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                return false;
            }

            if ($this->isTokenExpired()) {
                $this->logger->logError("Expired CSRF token detected");
                return false;
            }

            return $this->verifyToken($token);

        } catch (Exception $e) {
            $this->logger->logError("CSRF validation error: " . $e->getMessage());
            return false;
        }
    }

    private function isValidTokenFormat(string $token): bool
    {
        return preg_match('/^[a-f0-9]{64}$/', $token) === 1;
    }

    private function isTokenExpired(): bool
    {
        $tokenAge = time() - ($_SESSION['csrf_token_time'] ?? 0);
        return $tokenAge > 3600;
    }

    private function verifyToken(string $token): bool
    {
        $isValid = hash_equals($_SESSION['csrf_token'], $token);
        if (!$isValid) {
            $this->logger->logError("Invalid CSRF token provided from IP: " . $this->logger->anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        }
        return $isValid;
    }

    public function validateSession(): bool
    {
        try {
            if (!$this->hasValidSessionData()) {
                $this->logger->logError("Session validation failed - missing user_id or authenticated flag");
                return false;
            }

            if (!$this->hasConsistentSession()) {
                $this->logger->logError("Session validation failed - IP or User-Agent mismatch");
                return false;
            }

            return $_SESSION['authenticated'] === true;

        } catch (Exception $e) {
            $this->logger->logError("Session validation error: " . $e->getMessage());
            return false;
        }
    }

    private function hasValidSessionData(): bool
    {
        return !empty($_SESSION['user_id']) && !empty($_SESSION['authenticated']);
    }

    private function hasConsistentSession(): bool
    {
        $ipMatch = ($_SESSION['ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '');
        $agentMatch = ($_SESSION['user_agent'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
        return $ipMatch && $agentMatch;
    }

    public function validateAdminAccess(PDO $db): bool
    {
        try {
            if (!$this->validateSession()) {
                throw new Exception('Unauthorized - Invalid session', 401);
            }

            $userId = $_SESSION['user_id'] ?? 0;
            $isAdmin = $this->checkAdminStatus($db, $userId);

            if ($isAdmin === false) {
                $this->logger->logError("Admin check failed - user ID {$userId} not found in database");
                return false;
            }

            return (bool)$isAdmin;

        } catch (PDOException $e) {
            $this->logger->logError("Database error during admin validation: " . $e->getMessage());
            throw new RuntimeException('Authorization check failed', 500, $e);
        } catch (Exception $e) {
            $this->logger->logError("Admin validation error: " . $e->getMessage());
            throw $e;
        }
    }

    private function checkAdminStatus(PDO $db, int $userId): bool
    {
        $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        if (!$stmt->execute([$userId])) {
            throw new RuntimeException('Database query failed');
        }
        return $stmt->fetchColumn();
    }
}