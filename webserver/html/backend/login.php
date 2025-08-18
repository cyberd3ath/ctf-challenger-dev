<?php
declare(strict_types=1);

header('Content-Type: application/json');

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

    private array $session;
    private array $server;
    private array $post;

    public function __construct(
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        array $session = null,
        array $server = null,
        array $post = null
    )
    {
        if($session)
            $this->session =& $session;
        else
            $this->session =& $_SESSION;

        $this->server = $server ?? $_SERVER;
        $this->post = $post ?? $_POST;

        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;

        $this->initSession();
        $this->validateRequestMethod();
        $this->checkAlreadyAuthenticated();
        $this->logger->logDebug("Initialized LoginHandler with Session ID: " . session_id());
    }

    private function initSession()
    {
        $this->securityHelper->initSecureSession();
    }

    private function validateRequestMethod()
    {
        $this->isPost = $this->server['REQUEST_METHOD'] === 'POST';
    }

    private function checkAlreadyAuthenticated()
    {
        if ($this->securityHelper->validateSession() && !empty($this->session['authenticated'])) {
            $this->handleAlreadyAuthenticated();
        }
    }

    private function handleAlreadyAuthenticated()
    {
        $redirectUrl = '/dashboard';
        $userId = $this->session['user_id'];
        $username = $this->session['username'];
        $ip = $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown');

        $this->logger->logWarning("User already authenticated - User ID: {$userId}, Username: {$username}, IP: {$ip}");

        $existingCsrf = $this->session['csrf_token'] ?? $this->securityHelper->generateCsrfToken();
        if (!isset($this->session['csrf_token'])) {
            $this->session['csrf_token'] = $existingCsrf;
            $this->logger->logDebug("Generated new CSRF token for user ID: {$userId}");
        }

        $this->setCsrfCookie($existingCsrf);

        echo json_encode([
            'success' => true,
            'redirect' => $redirectUrl,
            'csrf_token' => $existingCsrf
        ]);
        exit;
    }

    public function handleRequest()
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

    private function processLogin()
    {
        $this->parseInput();
        $this->validateInput();
        $this->authenticateUser();
    }

    private function parseInput()
    {
        $this->csrfToken = $this->post['csrf_token'] ?? '';
        $this->username = trim($this->post['username'] ?? '');
        $this->password = $this->post['password'] ?? '';
    }

    private function validateInput()
    {
        if (empty($this->csrfToken)) {
            $this->logger->logError("Empty CSRF token - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid request token.', 403);
        }

        if (!$this->securityHelper->validateCsrfToken($this->csrfToken)) {
            $this->logger->logError("Invalid CSRF token - Received: {$this->csrfToken}, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown') .", Username: {$this->username}");
            throw new Exception('Invalid request token.', 403);
        }

        if (empty($this->username)) {
            $this->logger->logError("Empty username provided - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Username is required.', 400);
        }

        if (empty($this->password)) {
            $this->logger->logError("Empty password provided - Username: {$this->username}, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Password is required.', 400);
        }
    }

    private function authenticateUser()
    {
        $this->pdo = $this->databaseHelper->getPDO();

        $user = $this->findUserByUsername();
        $this->verifyPassword($user);
        $this->updateLastLogin($user['id']);
        $this->initializeUserSession($user);
        $this->sendSuccessResponse($user);
    }

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
            $this->logger->logError("User not found - Username: {$this->username}, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid username or password.', 401);
        }

        return $user;
    }

    private function verifyPassword(array $user)
    {
        if (!password_verify($this->password, $user['password_hash'])) {
            $this->logger->logError("Invalid password attempt - User ID: {$user['id']}, Username: {$this->username}, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Invalid username or password.', 401);
        }
    }

    private function updateLastLogin(int $userId)
    {
        $update = $this->pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = :id");
        $update->execute(['id' => $userId]);
    }

    private function initializeUserSession(array $user)
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

    private function sendSuccessResponse(array $user)
    {
        $newCsrf = $this->securityHelper->generateCsrfToken();
        $this->setCsrfCookie($newCsrf);

        echo json_encode([
            'success' => true,
            'message' => 'Login successful.',
            'redirect' => '/dashboard',
            'csrf_token' => $newCsrf
        ]);
        exit;
    }

    private function setCsrfCookie(string $token)
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

    private function respondWithError(string $message, int $statusCode, string $type = 'general')
    {
        http_response_code($statusCode);
        echo json_encode([
            'success' => false,
            'type' => $type,
            'message' => $message
        ]);
        exit;
    }
}

try {
    $handler = new LoginHandler();
    $handler->handleRequest();
} catch (Throwable $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $this->logger->logError("Error in login endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}