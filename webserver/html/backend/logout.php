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

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private array $session;
    private array $server;

    public function __construct(
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        array $session = null,
        array $server = null
    )
    {
        if($session)
            $this->session =& $session;
        else
            $this->session =& $_SESSION;

        $this->server = $server ?? $_SERVER;

        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;

        $this->initSession();
        $this->validateSession();
        $this->parseRequest();
        $this->logger->logDebug("Initialized LogoutHandler for user ID: {$this->userId}");
    }

    private function initSession()
    {
        $this->securityHelper->initSecureSession();
    }

    private function validateSession()
    {
        if (!$this->securityHelper->validateSession() || empty($this->session['authenticated'])) {
            $this->logger->logWarning("Unauthorized logout attempt - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Unauthorized - Please login', 401);
        }

        $this->userId = $this->session['user_id'] ?? 'unknown';
    }

    private function parseRequest()
    {
        $this->csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
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
        if (!$this->securityHelper->validateCsrfToken($this->csrfToken)) {
            $this->logger->logError("Invalid CSRF token during logout - User ID: {$this->userId}, Token: {$this->csrfToken}, IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
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

        $this->logger->logError("Logout failed - Code: {$code}, Message: " . $e->getMessage() .
            ", User ID: {$this->userId}" .
            ", IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));

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
    $this->logger->logError("Error in logout endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}