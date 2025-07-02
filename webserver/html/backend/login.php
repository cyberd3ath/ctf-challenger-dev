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

    public function __construct()
    {
        $this->initSession();
        $this->validateRequestMethod();
        $this->checkAlreadyAuthenticated();
        logDebug("Initialized LoginHandler with Session ID: " . session_id());
    }

    private function initSession()
    {
        init_secure_session();
    }

    private function validateRequestMethod()
    {
        $this->isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
    }

    private function checkAlreadyAuthenticated()
    {
        if (validate_session() && !empty($_SESSION['authenticated'])) {
            $this->handleAlreadyAuthenticated();
        }
    }

    private function handleAlreadyAuthenticated()
    {
        $redirectUrl = '/dashboard';
        $userId = $_SESSION['user_id'];
        $username = $_SESSION['username'];
        $ip = $_SERVER['REMOTE_ADDR'];

        logWarning("User already authenticated - User ID: {$userId}, Username: {$username}, IP: {$ip}");

        $existingCsrf = $_SESSION['csrf_token'] ?? generate_csrf_token();
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = $existingCsrf;
            logDebug("Generated new CSRF token for user ID: {$userId}");
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
            logError("Database error during login: " . $e->getMessage());
            $this->respondWithError('A database error occurred.', 500, 'server');
        } catch (Exception $e) {
            logError("Login error: " . $e->getMessage());
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
        $this->csrfToken = $_POST['csrf_token'] ?? '';
        $this->username = trim($_POST['username'] ?? '');
        $this->password = $_POST['password'] ?? '';
    }

    private function validateInput()
    {
        if (empty($this->csrfToken)) {
            logError("Empty CSRF token - IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Invalid request token.', 403);
        }

        if (!validate_csrf_token($this->csrfToken)) {
            logError("Invalid CSRF token - Received: {$this->csrfToken}, IP: {$_SERVER['REMOTE_ADDR']}, Username: {$this->username}");
            throw new Exception('Invalid request token.', 403);
        }

        if (empty($this->username)) {
            logError("Empty username provided - IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Username is required.', 400);
        }

        if (empty($this->password)) {
            logError("Empty password provided - Username: {$this->username}, IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Password is required.', 400);
        }
    }

    private function authenticateUser()
    {
        $this->pdo = getPDO();

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
            logError("User not found - Username: {$this->username}, IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Invalid username or password.', 401);
        }

        return $user;
    }

    private function verifyPassword(array $user)
    {
        if (!password_verify($this->password, $user['password_hash'])) {
            logError("Invalid password attempt - User ID: {$user['id']}, Username: {$this->username}, IP: {$_SERVER['REMOTE_ADDR']}");
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
        logDebug("Session regenerated - User ID: {$user['id']}, New Session ID: " . session_id());

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['authenticated'] = true;
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $_SESSION['last_activity'] = time();
        $_SESSION['username'] = $user['username'];
    }

    private function sendSuccessResponse(array $user)
    {
        $newCsrf = generate_csrf_token();
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
    logError("Error in login endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}