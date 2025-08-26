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

        ISystem $system = new SystemWrapper()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->get = $get;

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
        $csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
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
            $dateRange = $this->getDateRange();
            $params = [];
            $whereConditions = $this->buildWhereConditions($dateRange, $params);

            $baseQuery = "SELECT * FROM announcements";
            $countQuery = "SELECT COUNT(*) FROM announcements";

            if (!empty($whereConditions)) {
                $whereClause = " WHERE " . implode(" AND ", $whereConditions);
                $baseQuery .= $whereClause;
                $countQuery .= $whereClause;
            }

            $total = $this->getTotalCount($countQuery, $params);
            $announcements = $this->getPaginatedResults($baseQuery, $params);

            $this->sendResponse($announcements, $total);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in announcements route: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    private function getDateRange(): ?string
    {
        if ($this->rangeFilter === 'all') {
            return null;
        }

        $date = new DateTime();
        switch ($this->rangeFilter) {
            case 'today':
                $date->setTime(0, 0);
                break;
            case 'week':
                $date->modify('-1 week');
                break;
            case 'month':
                $date->modify('-1 month');
                break;
            case 'year':
                $date->modify('-1 year');
                break;
        }
        return $date->format('Y-m-d H:i:s');
    }

    private function buildWhereConditions($dateRange, &$params): array
    {
        $conditions = [];

        if ($this->importanceFilter !== 'all') {
            $conditions[] = "importance = :importance";
            $params['importance'] = $this->importanceFilter;
        }

        if ($dateRange) {
            $conditions[] = "created_at >= :date_range";
            $params['date_range'] = $dateRange;
        }

        return $conditions;
    }

    private function getTotalCount($query, $params)
    {
        $stmt = $this->pdo->prepare($query);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function getPaginatedResults($query, $params): array
    {
        $offset = ($this->page - 1) * $this->perPage;
        $query .= " ORDER BY created_at DESC, id ASC LIMIT :limit OFFSET :offset";

        $stmt = $this->pdo->prepare($query);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->bindValue(':limit', $this->perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

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