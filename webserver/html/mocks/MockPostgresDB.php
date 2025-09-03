<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Modules\PostgresContainer;
use Testcontainers\Wait\WaitForLog;

class MockPostgresDB
{
    private StartedGenericContainer $postgresContainer;
    private GenericContainer $container;
    private PDO $pdo;
    private string $initScriptPath;
    private ISystem $system;

    private string $dbName;
    private string $dbUser;
    private string $dbPassword;

    public function __construct(
        string $dbName = 'ctf-challenger',
        string $dbUser = 'testuser',
        string $dbPassword = 'testpass',
        string $initScriptPath = __DIR__ . '/../../../database/init.sql',
        ISystem $system = new SystemWrapper()
    )
    {
        $this->dbName = $dbName;
        $this->dbUser = $dbUser;
        $this->dbPassword = $dbPassword;

        $this->system = $system;
        $this->initScriptPath = $initScriptPath;

        putenv("DOCKER_HOST=tcp://localhost:2375");

        $maxTries = 5;
        $attempt = 0;
        while ($attempt < $maxTries) {
            try {

            $this->container = (new PostgresContainer("15"))
                ->withPostgresUser($dbUser)
                ->withPostgresPassword($dbPassword)
                ->withPostgresDatabase($dbName)
                ->withWait(new WaitForLog("database system is ready to accept connections", false, 10000));

            $this->postgresContainer = $this->container->start();
            break;
            } catch (Exception $e) {
                $attempt++;
                if ($attempt >= $maxTries) {
                    throw new RuntimeException("Failed to start Postgres container after $maxTries attempts: " . $e->getMessage());
                }
                sleep(2); // wait before retrying
            }
        }



        $this->pdo = new PDO(
            sprintf(
                'pgsql:host=%s;port=%d;dbname=%s',
                $this->postgresContainer->getHost(),
                $this->postgresContainer->getMappedPort(5432),
                $dbName
            ),
            $dbUser,
            $dbPassword
        );
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->initializeDatabase();
    }

    public function getPDO(): PDO
    {
        return $this->pdo;
    }

    private function initializeDatabase(): void
    {
        if ($this->system->file_exists($this->initScriptPath)) {
            $initSql = $this->system->file_get_contents($this->initScriptPath);
            $this->pdo->exec($initSql);

            $this->insertTestData();
        } else {
            throw new RuntimeException("Initialization script not found: " . $this->initScriptPath);
        }
    }

    private function insertTestData(): void
    {
        $this->pdo->exec("
            INSERT INTO users (id, username, email, password_hash, is_admin)
            VALUES (1, 'admin', 'admin@localhost.local', 'adminhash', true),
                   (2, 'testuser', 'test@test.test', crypt('testpass', gen_salt('bf')), false);
        ");

        $this->pdo->exec("
            INSERT INTO vpn_static_ips (vpn_static_ip, user_id) VALUES 
                ('10.64.0.2', 1),
                ('10.64.0.3', NULL),
                ('10.64.0.4', NULL),
                ('10.64.0.5', NULL),
                ('10.64.0.6', NULL),
                ('10.64.0.7', NULL),
                ('10.64.0.8', NULL),
                ('10.64.0.9', NULL),
                ('10.64.0.0', NULL),
                ('10.64.0.10', NULL),
                ('10.64.0.11', NULL);
        ");

        $this->pdo->exec("
            UPDATE users SET vpn_static_ip = '10.64.0.2' WHERE id = 1;
        ");

        $this->pdo->exec("
            INSERT INTO challenge_subnets (subnet, available) VALUES 
                ('10.128.0.0/24', true), 
                ('10.128.0.1/24', true), 
                ('10.128.0.2/24', true), 
                ('10.128.0.3/24', true), 
                ('10.128.0.4/24', true), 
                ('10.128.0.5/24', true), 
                ('10.128.0.6/24', true), 
                ('10.128.0.7/24', true), 
                ('10.128.0.8/24', true), 
                ('10.128.0.9/24', true);
        ");
    }

    public function __destruct()
    {
        if (isset($this->postgresContainer)) {
            $this->postgresContainer->stop();
        }
    }
}
