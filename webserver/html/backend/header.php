<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';

class ProfileStatusHandler
{
    private PDO $pdo;
    private ?int $userId;
    private bool $isLoggedIn;

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

        header('Content-Type: application/json');
        $this->initSession();
        $this->validateRequestMethod();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->isLoggedIn = $this->securityHelper->validateSession();
        $this->userId = $this->session['user_id'] ?? null;

        $this->logger->logDebug("Initialized ProfileStatusHandler for " . ($this->isLoggedIn ? "user ID: $this->userId" : "guest"));
    }

    private function initSession(): void
    {
        try {
            $this->securityHelper->initSecureSession();
        } catch (Exception $e) {
            $this->logger->logError("Session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 500);
        }
    }

    private function validateRequestMethod(): void
    {
        if ($this->server['REQUEST_METHOD'] !== 'GET') {
            $this->logger->logWarning("Invalid request method: " . $this->server['REQUEST_METHOD']);
            throw new RuntimeException('Method not allowed', 405);
        }
    }

    public function handleRequest(): void
    {
        try {
            $response = $this->buildResponse();
            $this->sendSuccessResponse($response);
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function buildResponse(): array
    {
        $response = ['is_logged_in' => $this->isLoggedIn];

        if ($this->isLoggedIn && $this->userId) {
            $userData = $this->getUserProfileData();
            $response = array_merge($response, $userData);
        }

        return $response;
    }

    private function getUserProfileData(): array
    {
        try {
            $stmt = $this->pdo->prepare("SELECT avatar_url, is_admin FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$result) {
                $this->logger->logError("User not found in database: $this->userId");
                throw new RuntimeException('User not found', 400);
            }

            return [
                'avatar_url' => $result['avatar_url'] ?? '/assets/avatars/default-avatar.png',
                'is_admin' => (bool)$result['is_admin']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error for user $this->userId: " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve profile data', 500);
        }
    }

    private function sendSuccessResponse(array $data): void
    {
        echo json_encode([
            'success' => true,
            'data' => $data
        ]);
    }

    private function handleError(Exception $e): void
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $errorCode >= 500 ? 'An internal server error occurred' : $e->getMessage();

        if ($errorCode === 401) {
            session_unset();
            session_destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
        }

        if ($errorCode >= 500) {
            $this->logger->logError("Internal error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
        } else {
            $this->logger->logWarning("Profile status error: " . $e->getMessage());
        }

        http_response_code($errorCode);
        echo json_encode([
            'success' => false,
            'message' => $errorMessage,
            'redirect' => $errorCode === 401 ? '/login' : null
        ]);
    }
}

try {
    $handler = new ProfileStatusHandler();
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger();
    $logger->logError("Error in header endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}