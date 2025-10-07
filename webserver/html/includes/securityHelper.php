<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class SecurityHelper implements ISecurityHelper
{    
    private const array SECURITY_HEADERS = [
        "X-Content-Type-Options: nosniff", "X-Frame-Options: SAMEORIGIN", "X-XSS-Protection: 1; mode=block", "Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; connect-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';", "Referrer-Policy: strict-origin-when-cross-origin", "Permissions-Policy: geolocation=(), camera=(), microphone=(), fullscreen=*, payment=()", "Cross-Origin-Resource-Policy: same-origin", "X-Permitted-Cross-Domain-Policies: none"
    ];

    private ILogger $logger;
    private ISession $session;
    private ISystem $system;
    private IServer $server;

    public function __construct(
        ILogger $logger = null,
        ISession $session = new Session(),
        ISystem $system = new SystemWrapper(),
        IServer $server = new Server()
    )
    {
        $this->logger = $logger ?? new Logger(system: $system);
        $this->session = $session;
        $this->system = $system;
        $this->server = $server;
    }

    public function initSecureSession(): void
    {
        try {
            $this->setSecureCookieParams();
            $this->startSession();
            $this->regenerateSessionId();
            $this->addSecurityHeaders();

            $this->logger->logDebug("Secure session initialized for IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));

        } catch (CustomException $e) {
            $this->logger->logError("Secure session initialization failed: " . $e->getMessage());
            throw new CustomException('Session initialization error', 0);
        } // @codeCoverageIgnoreStart
        catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during secure session initialization: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }
        // @codeCoverageIgnoreEnd
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

        if (!$this->session->set_cookie_params($cookieParams)) {
            throw new CustomException('Failed to set secure session cookie parameters');
        }
    }

    private function startSession(): void
    {
        if ($this->session->status() === PHP_SESSION_NONE && !$this->session->start()) {
            throw new CustomException('Failed to start secure session');
        }
    }

    private function regenerateSessionId(): void
    {
        if (empty($this->session['initiated'])) {
            $this->session->regenerate_id(true);
            $this->session['initiated'] = true;
            $this->session['ip'] = $this->server['REMOTE_ADDR'] ?? '';
            $this->session['user_agent'] = $this->server['HTTP_USER_AGENT'] ?? '';
        }
    }

    public function addSecurityHeaders(): void
    {
        try {
            foreach (self::SECURITY_HEADERS as $header) {
                header($header);
            }
            $this->logger->logDebug("Security headers added for IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
        } catch (CustomException $e) {
            $this->logger->logError("Failed to add security headers: " . $e->getMessage());
        } // @codeCoverageIgnoreStart
        catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error while adding security headers: " . $e->getMessage());
        }
        // @codeCoverageIgnoreEnd
    }

    public function generateCsrfToken(): string
    {
        try {
            if (empty($this->session)) {
                throw new CustomException('Session not initialized');
            }

            $token = bin2hex(random_bytes(32));
            if ($token == false) {
                throw new CustomException('CSRF token generation failed');
            }

            $this->session['csrf_token'] = $token;
            $this->session['csrf_token_time'] = $this->system->time();

            $this->logger->logDebug("CSRF token generated for session ID: " . $this->session->id());
            return $token;

        } catch (CustomException $e) {
            $this->logger->logError("CSRF token generation failed: " . $e->getMessage());
            throw new CustomException('Security token error', 0);
        } catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during CSRF token generation: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }
    }

    public function validateCsrfToken(string $token): bool
    {
        try {
            if (empty($this->session['csrf_token']) || empty($token)) {
                $this->logger->logError("Missing CSRF token in session or request");
                return false;
            }

            if (!$this->isValidTokenFormat($token)) {
                $this->logger->logError("Invalid CSRF token format from IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
                return false;
            }

            if ($this->isTokenExpired()) {
                $this->logger->logError("Expired CSRF token detected");
                return false;
            }

            return $this->verifyToken($token);

        } catch (CustomException $e) {
            $this->logger->logError("CSRF validation error: " . $e->getMessage());
            return false;
        } catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during CSRF validation: " . $e->getMessage());
            return false;
        }
    }

    private function isValidTokenFormat(string $token): bool
    {
        return preg_match('/^[a-f0-9]{64}$/', $token) === 1;
    }

    private function isTokenExpired(): bool
    {
        $tokenAge = $this->system->time() - ($this->session['csrf_token_time'] ?? 0);
        return $tokenAge > 3600;
    }

    private function verifyToken(string $token): bool
    {
        $isValid = hash_equals($this->session['csrf_token'], $token);
        if (!$isValid) {
            $this->logger->logError("Invalid CSRF token provided from IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
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
                $this->logger->logDebug(($this->session['ip'] ?? 'unknown') . " vs " . ($this->server['REMOTE_ADDR'] ?? 'unknown'));
                $this->logger->logDebug(($this->session['user_agent'] ?? 'unknown ') . " vs " . ($this->server['HTTP_USER_AGENT'] ?? 'unknown'));
                return false;
            }

            return $this->session['authenticated'] === true;

        } catch (CustomException $e) {
            $this->logger->logError("Session validation error: " . $e->getMessage());
            return false;
        } catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during session validation: " . $e->getMessage());
            return false;
        }
    }

    private function hasValidSessionData(): bool
    {
        return !empty($this->session['user_id']) && !empty($this->session['authenticated']);
    }

    private function hasConsistentSession(): bool
    {
        $ipMatch = ($this->session['ip'] ?? '') === ($this->server['REMOTE_ADDR'] ?? '');
        $agentMatch = ($this->session['user_agent'] ?? '') === ($this->server['HTTP_USER_AGENT'] ?? '');
        return $ipMatch && $agentMatch;
    }

    public function validateAdminAccess(PDO $db): bool
    {
        try {
            if (!$this->validateSession()) {
                throw new CustomException('Unauthorized - Invalid session', 401);
            }

            $userId = $this->session['user_id'] ?? 0;
            $isAdmin = $this->checkAdminStatus($db, $userId);

            if (!$isAdmin) {
                $this->logger->logError("Admin check failed - user ID {$userId} not found in database");
                return false;
            }

            return true;

        } catch (PDOException $e) {
            $this->logger->logError("Database error during admin validation: " . $e->getMessage());
            throw new CustomException('Authorization check failed', 500);
        } catch (CustomException $e) {
            $this->logger->logError("Admin validation error: " . $e->getMessage());
            throw $e;
        } catch (Exception $e) {
            // most likely not reachable, gonna leave it here for safety
            $this->logger->logError("Unexpected error during admin validation: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }
    }

    private function checkAdminStatus(PDO $db, int $userId): bool
    {
        $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        if (!$stmt->execute([$userId])) {
            throw new CustomException('Database query failed');
        }
        return $stmt->fetchColumn();
    }
}