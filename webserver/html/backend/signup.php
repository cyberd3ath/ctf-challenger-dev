<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/curlHelper.php';
require_once __DIR__ . '/../includes/auth.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class RegistrationHandler
{
    private PDO $pdo;
    private string $username;
    private string $email;
    private string $password;
    private string $confirmPassword;
    private string $csrfToken;
    private array $generalConfig;

    public function __construct(array $generalConfig)
    {
        $this->generalConfig = $generalConfig;
        $this->initSession();
        $this->validateRequestMethod();
        $this->parseInput();
        logDebug("Initialized RegistrationHandler with Session ID: " . session_id());
    }

    private function initSession()
    {
        init_secure_session();
    }

    private function validateRequestMethod()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new Exception('Invalid request method', 400);
        }
    }

    private function parseInput()
    {
        $this->csrfToken = $_POST['csrf_token'] ?? '';
        $this->username = trim($_POST['username'] ?? '');
        $this->email = trim($_POST['email'] ?? '');
        $this->password = $_POST['password'] ?? '';
        $this->confirmPassword = $_POST['confirm-password'] ?? '';
    }

    public function handleRequest()
    {
        try {
            $this->validateInput();
            $this->validateCsrfToken();
            $this->checkCredentialsAvailability();
            $userId = $this->createUserAccount();
            $vpnIp = $this->assignVpnIp($userId);
            $this->generateAndSaveVpnConfig($userId);
            $this->initializeUserSession($userId);
            $this->sendSuccessResponse($userId, $vpnIp);
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function validateInput()
    {
        if (empty($this->username) || empty($this->email) || empty($this->password) || empty($this->confirmPassword)) {
            throw new Exception('All fields are required', 400);
        } elseif (strlen($this->username) < $this->generalConfig['user']['MIN_USERNAME_LENGTH']) {
            throw new Exception('Username must be at least' . $this->generalConfig['user']['MIN_USERNAME_LENGTH'] . 'characters long', 400);
        } elseif (strlen($this->username) > $this->generalConfig['user']['MAX_USERNAME_LENGTH']) {
            throw new Exception('Username must not extend ' . $this->generalConfig['user']['MAX_USERNAME_LENGTH'], 400);
        } elseif (!preg_match('/' . $this->generalConfig['user']['USERNAME_REGEX'] . '/', $this->username)) {
            throw new Exception("Username contains invalid characters only '_' is allowed", 400);
        }

        if (strlen($this->email) > $this->generalConfig['user']['MAX_EMAIL_LENGTH']) {
            throw new Exception('Email must not extend ' . $this->generalConfig['user']['MAX_EMAIL_LENGTH'], 400);
        } elseif (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format', 400);
        }

        if (strlen($this->password) < $this->generalConfig['user']['MIN_PASSWORD_LENGTH']) {
            throw new Exception('Password must be at least' . $this->generalConfig['user']['MIN_PASSWORD_LENGTH'] . 'characters long', 400);
        } elseif (strlen($this->password) > $this->generalConfig['user']['MAX_PASSWORD_LENGTH']) {
            throw new Exception('Password must not exceed ' . $this->generalConfig['user']['MAX_PASSWORD_LENGTH'], 400);
        }

        if ($this->password !== $this->confirmPassword) {
            throw new Exception('Passwords do not match', 400);
        }
    }

    private function validateCsrfToken()
    {
        if (!validate_csrf_token($this->csrfToken)) {
            logError("CSRF token validation failed from IP: {$_SERVER['REMOTE_ADDR']} with csrf_token={$this->csrfToken}");
            throw new Exception('Invalid CSRF token', 403);
        }
    }

    private function checkCredentialsAvailability()
    {
        $this->pdo = getPDO();

        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = :username");
        $stmt->execute(['username' => $this->username]);
        if ($stmt->fetch()) {
            logWarning("Registration attempt with existing username: {$this->username}");
            throw new Exception('Username already taken', 400);
        }

        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->execute(['email' => $this->email]);
        if ($stmt->fetch()) {
            logWarning("Registration attempt with existing email: {$this->email}");
            throw new Exception('Email already registered', 400);
        }
    }

    private function createUserAccount()
    {
        $passwordHash = password_hash($this->password, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            throw new Exception('Account creation failed', 500);
        }

        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO users (username, email, password_hash)
                VALUES (:username, :email, :password_hash)
                RETURNING id
            ");
            $stmt->execute([
                'username' => $this->username,
                'email' => $this->email,
                'password_hash' => $passwordHash
            ]);
            $userId = $stmt->fetchColumn();

            if (!$userId) {
                throw new Exception('Account creation failed', 500);
            }

            return $userId;
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("Database transaction failed: " . $e->getMessage());
            throw new Exception('Account creation failed', 500);
        }
    }

    private function assignVpnIp($userId)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT assign_lowest_vpn_ip(:user_id)");
            $stmt->execute(['user_id' => $userId]);
            $vpnIp = $stmt->fetchColumn();

            if ($vpnIp) {
                $stmt = $this->pdo->prepare("UPDATE users SET vpn_static_ip = :vpn_ip WHERE id = :id");
                $stmt->execute(['vpn_ip' => $vpnIp, 'id' => $userId]);
            }

            $this->pdo->commit();
            return $vpnIp;
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("VPN IP assignment failed: " . $e->getMessage());
            throw new Exception('VPN setup failed', 500);
        }
    }

    private function generateAndSaveVpnConfig($userId)
    {
        $configResponse = $this->generateVpnConfig($userId);

        if (!$configResponse['success']) {
            logError("VPN config generation failed for user {$userId}: " . $configResponse['message']);
            throw new Exception('VPN setup incomplete', 500);
        }

        $configSaved = $this->saveVpnConfig($userId, $configResponse['config_content']);
        if (!$configSaved) {
            logError("Failed to save VPN config file for user {$userId}");
            throw new Exception('VPN setup incomplete', 500);
        }
    }

    private function generateVpnConfig($userId)
    {
        try {
            $result = makeBackendRequest(
                '/create-user-config',
                'POST',
                getBackendHeaders(),
                ['user_id' => $userId]
            );

            if (!$result['success']) {
                $error = $result['error'] ?? 'HTTP ' . $result['http_code'];
                logError("VPN config API failed: {$error}");
                return [
                    'success' => false,
                    'message' => 'Backend request failed: ' . ($result['error'] ?? 'HTTP ' . $result['http_code'])
                ];
            }

            $isFileDownload = false;
            if (isset($result['headers']['content-type'])) {
                $isFileDownload = strpos($result['headers']['content-type'], 'application/octet-stream') !== false;
            }

            if ($isFileDownload) {
                return [
                    'success' => true,
                    'config_content' => $result['response']
                ];
            }

            $jsonResponse = json_decode($result['response'], true);
            if (json_last_error() === JSON_ERROR_NONE) {
                if (isset($jsonResponse['error'])) {
                    logError("VPN config error: {$jsonResponse['error']}");
                    return [
                        'success' => false,
                        'message' => $jsonResponse['error']
                    ];
                }
                return $jsonResponse;
            }

            logError("Unexpected VPN config response format");
            return [
                'success' => false,
                'message' => 'Unexpected response format'
            ];
        } catch (Exception $e) {
            logError("VPN config generation error for user {$userId}: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Configuration service error'
            ];
        }
    }

    private function saveVpnConfig($userId, $configContent)
    {
        try {
            $configDir = '/var/lib/ctf-challenger/vpn-configs/';
            if (!file_exists($configDir) && !mkdir($configDir, 0755, true)) {
                throw new Exception('Error creating VPN config directory', 500);
            }

            $filename = $configDir . 'user_' . $userId . '.ovpn';
            $bytesWritten = file_put_contents($filename, $configContent);

            if ($bytesWritten === false) {
                throw new Exception('Error creating VPN config file', 500);
            }

            return true;
        } catch (Exception $e) {
            logError("Config save failed: " . $e->getMessage());
            return false;
        }
    }

    private function initializeUserSession($userId)
    {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['last_activity'] = time();
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $this->username;

        $newCsrf = generate_csrf_token();
        setcookie(
            'csrf_token',
            $newCsrf,
            [
                'expires' => time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'samesite' => 'Strict'
            ]
        );

        logInfo("Successful registration for user {$userId}");
    }

    private function sendSuccessResponse($userId, $vpnIp)
    {
        echo json_encode([
            'success' => true,
            'message' => 'Registration successful',
            'user_id' => $userId,
            'vpn_ip' => $vpnIp
        ]);
        exit;
    }

    private function handleError(Exception $e)
    {
        $code = $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 400;
        http_response_code($code);

        logError("Registration error: " . $e->getMessage() . " [Code: {$code}]");

        echo json_encode([
            'success' => false,
            'message' => $e->getMessage(),
            'error_code' => $code
        ]);
        exit;
    }
}

try {
    $handler = new RegistrationHandler($generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in signup endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}