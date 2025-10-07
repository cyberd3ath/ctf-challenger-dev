<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class AnnouncementsHandler
{
    private PDO $pdo;
    private int $page;
    private int $perPage = 10;
    private string $importanceFilter;
    private string $rangeFilter;
    private array $config;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IGet $get;
    private ICookie $cookie;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,

        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),
        IGet $get = new Get(),

        ISystem $system = new SystemWrapper(),
        ICookie $cookie = new Cookie()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->get = $get;
        $this->cookie = $cookie;

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->logger = $logger ?? new Logger(system: $system);

        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->parseInputParameters();
        $this->logger->logDebug("Initialized AnnouncementsHandler");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning('Unauthorized access attempt to announcements route');
            throw new Exception('Unauthorized', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        $csrfToken = $this->cookie['csrf_token'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning('Invalid CSRF token attempt from user ID: ' . ($this->session['user_id'] ?? 'unknown'));
            throw new Exception('Invalid CSRF token', 403);
        }
    }

    /**
     * @throws Exception
     */
    private function parseInputParameters(): void
    {
        $this->page = (int)$this->get['page'] ?? 1;
        $this->page = max($this->page, 1);

        $this->importanceFilter = $this->get['importance'] ?? 'all';
        if (!in_array($this->importanceFilter, $this->config['filters']['IMPORTANCE_LEVELS'])) {
            $this->logger->logWarning('Invalid importance filter provided: ' . $this->importanceFilter);
            throw new Exception('Invalid importance value', 400);
        }

        $this->rangeFilter = $this->get['range'] ?? 'all';
        if (!in_array($this->rangeFilter, $this->config['filters']['ACTIVITY_RANGES'])) {
            $this->logger->logWarning('Invalid range filter provided: ' . $this->rangeFilter);
            throw new Exception('Invalid date range value', 400);
        }
    }

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            $total = $this->getTotalCount();
            $announcements = $this->getPaginatedResults();

            $this->sendResponse($announcements, $total);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in announcements route: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    private function getTotalCount(): int
    {
        $stmt = $this->pdo->prepare("
            SELECT get_filtered_announcements_count(:importance, :date_range) AS total
        ");

        $stmt->execute(
            [
                'importance' => $this->importanceFilter === 'all' ? null : $this->importanceFilter,
                'date_range' => $this->rangeFilter === 'all' ? null : $this->rangeFilter
            ]
        );
        return $stmt->fetchColumn();
    }

    private function getPaginatedResults(): array
    {
        $offset = ($this->page - 1) * $this->perPage;

        $stmt = $this->pdo->prepare("
            SELECT 
                id,
                title,
                content,
                short_description,
                importance,
                category,
                author,
                created_at,
                updated_at
            FROM get_filtered_announcements(:importance, :date_range, :limit, :offset)
        ");

        $stmt->execute(
            [
                'importance' => $this->importanceFilter === 'all' ? null : $this->importanceFilter,
                'date_range' => $this->rangeFilter === 'all' ? null : $this->rangeFilter,
                'limit' => $this->perPage,
                'offset' => $offset
            ]
        );

        $announcements = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $announcements[] = $this->formatAnnouncement($row);
        }
        return $announcements;
    }

    private function formatAnnouncement($row): array
    {
        return [
            'id' => $row['id'],
            'title' => htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'),
            'content' => htmlspecialchars($row['content'], ENT_QUOTES, 'UTF-8'),
            'importance' => $row['importance'],
            'category' => htmlspecialchars($row['category'] ?? '', ENT_QUOTES, 'UTF-8'),
            'author' => htmlspecialchars($row['author'], ENT_QUOTES, 'UTF-8'),
            'date' => $row['created_at']
        ];
    }

    private function sendResponse($announcements, $total): void
    {
        echo json_encode([
            'success' => true,
            'data' => [
                'announcements' => $announcements,
                'total' => (int)$total,
                'page' => $this->page,
                'per_page' => $this->perPage,
                'total_pages' => ceil($total / $this->perPage)
            ]
        ]);
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');
    $config = require __DIR__ . '/../config/backend.config.php';

    $handler = new AnnouncementsHandler(config: $config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger();
    $logger->logError("Error in announcements endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}

// @codeCoverageIgnoreEnd