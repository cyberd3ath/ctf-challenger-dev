<?php
declare(strict_types=1);

require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable("/var/www");
$dotenv->load();

interface IDatabaseHelper
{
    public function __construct(ILogger $logger = new Logger());
    public function getPDO(): PDO;
}


class DatabaseHelper implements IDatabaseHelper
{
    private ?PDO $pdoInstance;

    private ILogger $logger;

    public function __construct(ILogger $logger = new Logger())
    {
        $this->logger = $logger;
        $this->pdoInstance = null;
    }
    
    public function getPDO(): PDO
    {
        try {
            if ($this->pdoInstance === null) {
                $this->pdoInstance = $this->createConnection();
                $this->logger->logInfo("Database connection established successfully");
            }
            return $this->pdoInstance;

        } catch (PDOException $e) {
            $this->logger->logError("Database connection failed: " . $e->getMessage());
            $this->sendErrorResponse();
        } catch (Exception $e) {
            $this->logger->logError("Unexpected error during database connection: " . $e->getMessage());
            $this->sendErrorResponse();
        }

        // If we reach here, something went wrong
        throw new RuntimeException('Database connection error');
    }

    private function createConnection(): PDO
    {
        $host = $_ENV['DB_HOST'] ?? '';
        $db = $_ENV['DB_NAME'] ?? '';
        $user = $_ENV['DB_USER'] ?? '';
        $pass = $_ENV['DB_PASSWORD'] ?? '';
        $port = $_ENV['DB_PORT'] ?? '';

        if (empty($host) || empty($db) || empty($user) || empty($port)) {
            $this->logger->logError("Missing required database configuration parameters");
            throw new RuntimeException('Incomplete database configuration');
        }

        $dsn = "pgsql:host=$host;port=$port;dbname=$db";
        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
    }

    private function sendErrorResponse(): void
    {
        header('Content-Type: application/json');
        http_response_code(500);
        die(json_encode([
            'success' => false,
            'message' => 'Database service unavailable'
        ]));
    }
}