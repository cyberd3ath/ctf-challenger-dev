<?php
declare(strict_types=1);

require_once __DIR__ . '/logger.php';

class DatabaseHelper
{
    private static ?PDO $pdoInstance = null;

    public static function getPDO(): PDO
    {
        try {
            if (self::$pdoInstance === null) {
                self::loadEnvironment();
                self::$pdoInstance = self::createConnection();
                logInfo("Database connection established successfully");
            }
            return self::$pdoInstance;

        } catch (PDOException $e) {
            logError("Database connection failed: " . $e->getMessage());
            self::sendErrorResponse();
        } catch (Exception $e) {
            logError("Unexpected error during database connection: " . $e->getMessage());
            self::sendErrorResponse();
        }
    }

    private static function loadEnvironment(): void
    {
        try {
            require_once __DIR__ . '/../vendor/autoload.php';
            $dotenv = Dotenv\Dotenv::createImmutable("/var/www");
            $dotenv->load();
        } catch (Exception $e) {
            logError("Environment loading failed: " . $e->getMessage());
            throw new RuntimeException('Environment configuration error', 0, $e);
        }
    }

    private static function createConnection(): PDO
    {
        $host = $_ENV['DB_HOST'] ?? '';
        $db = $_ENV['DB_NAME'] ?? '';
        $user = $_ENV['DB_USER'] ?? '';
        $pass = $_ENV['DB_PASSWORD'] ?? '';
        $port = $_ENV['DB_PORT'] ?? '';

        if (empty($host) || empty($db) || empty($user) || empty($port)) {
            logError("Missing required database configuration parameters");
            throw new RuntimeException('Incomplete database configuration');
        }

        $dsn = "pgsql:host=$host;port=$port;dbname=$db";
        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
    }

    private static function sendErrorResponse(): void
    {
        header('Content-Type: application/json');
        http_response_code(500);
        die(json_encode([
            'success' => false,
            'message' => 'Database service unavailable'
        ]));
    }
}

function getPDO(): PDO
{
    return DatabaseHelper::getPDO();
}