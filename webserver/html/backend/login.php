<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

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
    
    private ISystem $system;

    public function __construct(
        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),
        IPost $post = new Post(),
        ISystem $system = new SystemWrapper()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->post = $post;

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(system: $system);
        
        $this->system = $system;

        $this->initSession();
        $this->validateRequestMethod();
        $this->checkAlreadyAuthenticated();
        $this->logger->logDebug("Initialized LoginHandler with Session ID: " . $this->session->id());
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

    private function handleAlreadyAuthenticated(): void
    {
        $redirectUrl = '/dashboard';
        $userId = $this->session['user_id'];
        $username = $this->session['username'];
        $ip = $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown');

        $this->logger->logWarning("User already authenticated - User ID: $userId, Username: $username, IP: $ip");

        if (!isset($this->session['csrf_token'])) {
            $this->securityHelper->generateCsrfToken();
            $this->logger->logDebug("Generated new CSRF token for user ID: $userId");
        }

        $csrf = $this->session['csrf_token'];

        $this->setCsrfCookie($csrf);

        echo json_encode([
            'success' => true,
            'redirect' => $redirectUrl,
            'csrf_token' => $csrf
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
    private function processLogin(): void
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
    private function authenticateUser(): void
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
        $update = $this->pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = :id");
        $update->execute(['id' => $userId]);
    }

    private function initializeUserSession(array $user): void
    {
        $this->session->regenerate_id(true);
        $this->logger->logDebug("Session regenerated - User ID: {$user['id']}, New Session ID: " . $this->session->id());

        $this->session['user_id'] = $user['id'];
        $this->session['authenticated'] = true;
        $this->session['ip'] = $this->server['REMOTE_ADDR'] ?? '';
        $this->session['user_agent'] = $this->server['HTTP_USER_AGENT'] ?? '';
        $this->session['last_activity'] = $this->system->time();
        $this->session['username'] = $user['username'];
    }

    private function sendSuccessResponse(): void
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
        $this->system->setcookie(
            'csrf_token',
            $token,
            [
                'expires' => $this->system->time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'samesite' => 'Strict'
            ]
        );
    }

    private function respondWithError(string $message, int $statusCode, string $type = 'general'): void
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

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');

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