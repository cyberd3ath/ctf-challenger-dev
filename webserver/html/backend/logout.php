<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';

class LogoutHandler
{
    private ?int $userId;
    private string $csrfToken;

    public function __construct()
    {
        $this->initSession();
        $this->validateSession();
        $this->parseRequest();
        logDebug("Initialized LogoutHandler for user ID: {$this->userId}");
    }

    private function initSession()
    {
        init_secure_session();
    }

    private function validateSession()
    {
        if (!validate_session() || empty($_SESSION['authenticated'])) {
            logWarning("Unauthorized logout attempt - IP: {$_SERVER['REMOTE_ADDR']}, Session: " . json_encode($_SESSION));
            throw new Exception('Unauthorized - Please login', 401);
        }

        $this->userId = $_SESSION['user_id'] ?? 'unknown';
    }

    private function parseRequest()
    {
        $this->csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    }

    public function handleRequest()
    {
        try {
            $this->validateCsrfToken();
            $this->destroySession();
            $this->sendSuccessResponse();
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function validateCsrfToken()
    {
        if (!validate_csrf_token($this->csrfToken)) {
            logError("Invalid CSRF token during logout - User ID: {$this->userId}, Token: {$this->csrfToken}, IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Invalid security token', 403);
        }
    }

    private function destroySession()
    {
        session_unset();
        session_destroy();

        $this->expireSessionCookies();
    }

    private function expireSessionCookies()
    {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            [
                'expires' => time() - 3600,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite']
            ]
        );

        setcookie(
            'csrf_token',
            '',
            [
                'expires' => time() - 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]
        );
    }

    private function sendSuccessResponse()
    {
        echo json_encode([
            'success' => true,
            'message' => 'Logged out successfully'
        ]);
        exit;
    }

    private function handleError(Exception $e)
    {
        $code = $e->getCode() ?: 500;
        http_response_code($code);

        logError("Logout failed - Code: {$code}, Message: " . $e->getMessage() .
            ", User ID: {$this->userId}" .
            ", IP: {$_SERVER['REMOTE_ADDR']}");

        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
        exit;
    }
}

try {
    $handler = new LogoutHandler();
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in logout endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}