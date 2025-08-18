<?php
declare(strict_types=1);

use JetBrains\PhpStorm\NoReturn;

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/globals.php';
require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';

class LoginHandler
{
    private PDO $pdo;
    private bool $isPost;
    private string $username;
    private string $password;
    private string $csrfToken;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IPost $post;

    public function __construct(
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        ISession $session = new Session(),
        IServer $server = new Server(),
        IPost $post = new Post()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->post = $post;

        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;

        $this->initSession();
        $this->validateRequestMethod();
        $this->checkAlreadyAuthenticated();
        $this->logger->logDebug("Initialized LoginHandler with Session ID: " . session_id());
    }

    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();
    }

    private function validateRequestMethod(): void
    {
        $this->isPost = $this->server['REQUEST_METHOD'] === 'POST';
    }

    private function checkAlreadyAuthenticated(): void
    {
        if ($this->securityHelper->validateSession() && !empty($this->session['authenticated'])) {
            $this->handleAlreadyAuthenticated();
        }
    }

    #[NoReturn] private function handleAlreadyAuthenticated(): void
    {
        $redirectUrl = '/dashboard';
        $userId = $this->session['user_id'];
        $username = $this->session['username'];
        $ip = $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown');

        $this->logger->logWarning("User already authenticated - User ID: $userId, Username: $username, IP: $ip");

        $existingCsrf = $this->session['csrf_token'] ?? $this->securityHelper->generateCsrfToken();
        if (!isset($this->session['csrf_token'])) {
            $this->session['csrf_token'] = $existingCsrf;
            $this->logger->logDebug("Generated new CSRF token for user ID: $userId");
        }

        $this->setCsrfCookie($existingCsrf);

        echo json_encode([
            'success' => true,
            'redirect' => $redirectUrl,
            'csrf_token' => $existingCsrf
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }

    public function handleRequest(): void
    {
        try {
            if ($this->isPost) {
                $this->processLogin();
            }
        } catch (PDOException $e) {
            $this->logger->logError("Database error during login: " . $e->getMessage());
            $this->respondWithError('A database error occurred.', 500, 'server');
        } catch (Exception $e) {
            $this->logger->logError("Login error: " . $e->getMessage());
            $this->respondWithError($e->getMessage(), $e->getCode(), 'auth');
        }
    }

    /**
     * @throws Exception
     */
    #[NoReturn] private function processLogin(): void
    {
        $this->parseInput();
        $this->validateInput();
        $this->authenticateUser();
    }

    private function parseInput(): void
    {
        $this->csrfToken = $this->post['csrf_token'] ?? '';
        $this->username = trim($this->post['username'] ?? '');
        $this->password = $this->post['password'] ?? '';
    }

    /**
     * @throws Exception
     */
    private function validateInput(): void
    {
        if (empty($this->csrfToken)) {
            $this->logger->logError("Empty CSRF token - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid request token.', 403);
        }

        if (!$this->securityHelper->validateCsrfToken($this->csrfToken)) {
            $this->logger->logError("Invalid CSRF token - Received: $this->csrfToken, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown') .", Username: $this->username");
            throw new Exception('Invalid request token.', 403);
        }

        if (empty($this->username)) {
            $this->logger->logError("Empty username provided - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Username is required.', 400);
        }

        if (empty($this->password)) {
            $this->logger->logError("Empty password provided - Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Password is required.', 400);
        }
    }

    /**
     * @throws Exception
     */
    #[NoReturn] private function authenticateUser(): void
    {
        $this->pdo = $this->databaseHelper->getPDO();

        $user = $this->findUserByUsername();
        $this->verifyPassword($user);
        $this->updateLastLogin($user['id']);
        $this->initializeUserSession($user);
        $this->sendSuccessResponse();
    }

    /**
     * @throws Exception
     */
    private function findUserByUsername()
    {
        $stmt = $this->pdo->prepare("
            SELECT id, username, password_hash
            FROM users
            WHERE username = :username
            LIMIT 1
        ");
        $stmt->execute(['username' => $this->username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->logger->logError("User not found - Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid username or password.', 401);
        }

        return $user;
    }

    /**
     * @throws Exception
     */
    private function verifyPassword(array $user): void
    {
        if (!password_verify($this->password, $user['password_hash'])) {
            $this->logger->logError("Invalid password attempt - User ID: {$user['id']}, Username: $this->username, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid username or password.', 401);
        }
    }

    private function updateLastLogin(int $userId): void
    {
        $update = $this->pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = :id");
        $update->execute(['id' => $userId]);
    }

    private function initializeUserSession(array $user): void
    {
        session_regenerate_id(true);
        $this->logger->logDebug("Session regenerated - User ID: {$user['id']}, New Session ID: " . session_id());

        $this->session['user_id'] = $user['id'];
        $this->session['authenticated'] = true;
        $this->session['ip'] = $this->server['REMOTE_ADDR'] ?? '';
        $this->session['user_agent'] = $this->server['HTTP_USER_AGENT'] ?? '';
        $this->session['last_activity'] = time();
        $this->session['username'] = $user['username'];
    }

    #[NoReturn] private function sendSuccessResponse(): void
    {
        $newCsrf = $this->securityHelper->generateCsrfToken();
        $this->setCsrfCookie($newCsrf);

        echo json_encode([
            'success' => true,
            'message' => 'Login successful.',
            'redirect' => '/dashboard',
            'csrf_token' => $newCsrf
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }

    private function setCsrfCookie(string $token): void
    {
        setcookie(
            'csrf_token',
            $token,
            [
                'expires' => time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'samesite' => 'Strict'
            ]
        );
    }

    #[NoReturn] private function respondWithError(string $message, int $statusCode, string $type = 'general'): void
    {
        http_response_code($statusCode);
        echo json_encode([
            'success' => false,
            'type' => $type,
            'message' => $message
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }
}

try {
    $handler = new LoginHandler();
    $handler->handleRequest();
} catch (Throwable $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger();
    $logger->logError("Error in login endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}