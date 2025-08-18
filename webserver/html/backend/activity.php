<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
$config = require __DIR__ . '/../config/backend.config.php';

class ActivitiesHandler
{
    private PDO $pdo;
    private ?int $userId;
    private int $page;
    private int $perPage = 10;
    private string $typeFilter;
    private string $rangeFilter;
    private string $categoryFilter;
    private array $config;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private array $session;
    private array $server;
    private array $get;


    /**
     * @throws Exception
     */
    public function __construct(
        array $config,
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        array $session = null,
        array $server = null,
        array $get = null
    )
    {
        if($session)
            $this->session =& $session;
        else
            $this->session =& $_SESSION;

        $this->server = $server ?? $_SERVER;
        $this->get = $get ?? $_GET;

        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;

        $this->config = $config;
        $this->initSession();
        $this->validateRequest();
        $this->pdo = $this->databaseHelper->getPDO();
        $this->userId = $this->session['user_id'];
        $this->parseInputParameters();
        $this->logger->logDebug("Initialized ActivitiesHandler for user ID: $this->userId");
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning('Unauthorized access attempt to activities route');
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
        $this->page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, [
            'options' => ['default' => 1, 'min_range' => 1]
        ]);

        $this->typeFilter = $this->get['type'] ?? 'all';
        if (!in_array($this->typeFilter, $this->config['filters']['ACTIVITY_TYPES'])) {
            $this->logger->logWarning('Invalid type filter provided: ' . $this->typeFilter);
            throw new Exception('Invalid activity type filter', 400);
        }

        $this->rangeFilter = $this->get['range'] ?? 'all';
        if (!in_array($this->rangeFilter, $this->config['filters']['ACTIVITY_RANGES'])) {
            $this->logger->logWarning('Invalid range filter provided: ' . $this->rangeFilter);
            throw new Exception('Invalid date range filter', 400);
        }

        $this->categoryFilter = $this->get['category'] ?? 'all';
        if (!in_array($this->categoryFilter, $this->config['filters']['CHALLENGE_CATEGORIES'])) {
            $this->logger->logWarning('Invalid category filter provided: ' . $this->categoryFilter);
            throw new Exception('Invalid category filter', 400);
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
                $date->modify('-1 day');
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

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            $dateRange = $this->getDateRange();
            $params = ['user_id' => $this->userId];

            $queries = $this->buildQueries($dateRange, $params);

            if (empty($queries)) {
                $this->sendResponse([], 0);
                return;
            }

            $combinedQuery = implode(" UNION ALL ", $queries);
            $total = $this->getTotalCount($combinedQuery, $params);
            $activities = $this->getPaginatedResults($combinedQuery, $params);

            $this->sendResponse($activities, $total);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in activities route: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    private function buildQueries($dateRange, &$params): array
    {
        $queries = [];

        if (in_array($this->typeFilter, ['all', 'solved', 'failed', 'active'])) {
            $queries[] = $this->buildChallengeQuery($dateRange, $params);
        }

        if (in_array($this->typeFilter, ['all', 'badges'])) {
            $queries[] = $this->buildBadgeQuery($dateRange, $params);
        }

        return $queries;
    }

    private function buildChallengeQuery($dateRange, &$params): string
    {
        $query = "
        WITH flag_counts AS (
            SELECT 
                challenge_template_id, 
                COUNT(id) AS total_flags
            FROM challenge_flags
            GROUP BY challenge_template_id
        ),
        user_flag_submissions AS (
            SELECT 
                cc.challenge_template_id,
                cc.id AS completion_id,
                cc.flag_id,
                cc.completed_at,
                ROW_NUMBER() OVER (
                    PARTITION BY cc.challenge_template_id 
                    ORDER BY cc.completed_at DESC
                ) AS submission_rank,
                COUNT(cf.id) OVER (
                    PARTITION BY cc.challenge_template_id
                ) AS user_submitted_flags
            FROM completed_challenges cc
            JOIN challenge_flags cf ON cc.flag_id = cf.id
            WHERE cc.user_id = :user_id
        ),
        challenge_attempts AS (
            SELECT 
                cc.id,
                cc.challenge_template_id,
                cc.started_at,
                cc.completed_at,
                cc.flag_id,
                ct.name,
                ct.category,
                cf.points,
                ROW_NUMBER() OVER (
                    PARTITION BY cc.challenge_template_id 
                    ORDER BY cc.started_at
                ) AS attempt_number,
                CASE
                    WHEN ufs.submission_rank = 1 AND ufs.user_submitted_flags = fc.total_flags THEN 'solved'
                    WHEN cc.flag_id IS NOT NULL THEN 'flag_submitted'
                    WHEN cc.completed_at IS NOT NULL AND cc.flag_id IS NULL THEN 'failed'
                    ELSE 'active'
                END AS status,
                CASE
                    WHEN cc.completed_at IS NOT NULL THEN cc.completed_at
                    ELSE cc.started_at
                END AS activity_date
            FROM completed_challenges cc
            JOIN challenge_templates ct ON ct.id = cc.challenge_template_id
            LEFT JOIN challenge_flags cf ON cf.id = cc.flag_id
            LEFT JOIN flag_counts fc ON fc.challenge_template_id = cc.challenge_template_id
            LEFT JOIN user_flag_submissions ufs ON ufs.completion_id = cc.id
            WHERE cc.user_id = :user_id
        )
        SELECT
            'challenge' AS activity_type,
            challenge_template_id AS item_id,
            name AS item_name,
            category,
            COALESCE(points, 0) AS points,
            status = 'solved' AS solved,
            attempt_number,
            started_at,
            completed_at,
            status,
            activity_date,
            NULL AS icon,
            NULL AS color,
            NULL AS description,
            'challenge' AS item_type,
            flag_id
        FROM challenge_attempts
        WHERE 1=1";

        if ($this->typeFilter === 'solved') {
            $query .= " AND status = 'solved'";
        } elseif ($this->typeFilter === 'failed') {
            $query .= " AND status = 'failed'";
        } elseif ($this->typeFilter === 'active') {
            $query .= " AND status = 'active'";
        }

        if ($this->categoryFilter !== 'all') {
            $query .= " AND category = :category";
            $params['category'] = $this->categoryFilter;
        }

        if ($dateRange) {
            $query .= " AND activity_date >= :date_range";
            $params['date_range'] = $dateRange;
        }

        return $query;
    }

    private function buildBadgeQuery($dateRange, &$params): string
    {
        $query = "SELECT 
            'badge' AS activity_type,
            b.id AS item_id,
            b.name AS item_name,
            NULL AS category,
            NULL AS points,
            true AS solved,
            1 AS attempt_number,
            ub.earned_at AS started_at,
            ub.earned_at AS completed_at,
            'badge' AS status,
            ub.earned_at AS activity_date,
            b.icon,
            b.color,
            b.description,
            'badge' AS item_type,
            NULL AS flag_id
        FROM user_badges ub
        JOIN badges b ON b.id = ub.badge_id
        WHERE ub.user_id = :user_id";

        if ($dateRange) {
            $query .= " AND ub.earned_at >= :date_range_badge";
            $params['date_range_badge'] = $dateRange;
        }

        return $query;
    }

    private function getTotalCount($query, $params)
    {
        $countQuery = "SELECT COUNT(*) FROM ($query) AS combined";
        $stmt = $this->pdo->prepare($countQuery);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function getPaginatedResults($query, $params): array
    {
        $offset = ($this->page - 1) * $this->perPage;
        $finalQuery = "$query ORDER BY activity_date DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->pdo->prepare($finalQuery);

        foreach ($params as $key => $val) {
            $stmt->bindValue($key, $val);
        }

        $stmt->bindValue(':limit', $this->perPage, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $activities = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $activities[] = $this->formatActivity($row);
        }

        return $activities;
    }

    private function formatActivity($row): array
    {
        $activity = [
            'type' => $row['status'],
            'title' => '',
            'item_id' => $row['item_id'],
            'item_name' => $row['item_name'],
            'item_type' => $row['item_type'],
            'category' => $row['category'],
            'points' => $row['points'],
            'timestamp' => $row['activity_date'],
            'time_ago' => $this->formatTimeAgo($row['activity_date']),
            'attempt_number' => $row['attempt_number'],
            'icon' => $row['icon'],
            'color' => $row['color'],
            'description' => $row['description']
        ];

        switch ($row['item_type']) {
            case 'badge':
                $activity['title'] = 'Badge earned: ' . $row['item_name'];
                break;

            case 'challenge':
                $activity['title'] = match ($row['status']) {
                    'solved' => 'Challenge solved (Attempt #' . $row['attempt_number'] . ')',
                    'failed' => 'Challenge failed (Attempt #' . $row['attempt_number'] . ')',
                    'flag_submitted' => 'Flag submitted',
                    default => 'Challenge attempt #' . $row['attempt_number']
                };

                if ($row['completed_at']) {
                    $elapsedSeconds = strtotime($row['completed_at']) - strtotime($row['started_at']);
                    $activity['duration'] = $this->formatDuration($elapsedSeconds);
                } else {
                    $activity['duration'] = 'In progress';
                }
                break;
        }

        return $activity;
    }

    private function sendResponse($activities, $total): void
    {
        echo json_encode([
            'success' => true,
            'data' => [
                'activities' => $activities,
                'total' => (int)$total,
                'page' => $this->page,
                'per_page' => $this->perPage
            ]
        ]);
    }

    private function formatTimeAgo($datetime): string
    {
        if (!$datetime) return 'Recently';

        try {
            $now = new DateTime();
            $then = new DateTime($datetime);
            $diff = $now->diff($then);

            if ($diff->y > 0) return $diff->y . ' year' . ($diff->y > 1 ? 's' : '') . ' ago';
            if ($diff->m > 0) return $diff->m . ' month' . ($diff->m > 1 ? 's' : '') . ' ago';
            if ($diff->d > 0) return $diff->d . ' day' . ($diff->d > 1 ? 's' : '') . ' ago';
            if ($diff->h > 0) return $diff->h . ' hour' . ($diff->h > 1 ? 's' : '') . ' ago';
            if ($diff->i > 0) return $diff->i . ' minute' . ($diff->i > 1 ? 's' : '') . ' ago';
            return 'Just now';
        } catch (Exception $e) {
            $this->logger->logError("Error formatting time ago: " . $e->getMessage());
            return 'Recently';
        }
    }

    private function formatDuration($seconds): string
    {
        if ($seconds < 60) return round($seconds) . 's';
        if ($seconds < 3600) return round($seconds / 60) . 'm';
        if ($seconds < 86400) return round($seconds / 3600, 1) . 'h';
        return round($seconds / 86400, 1) . 'd';
    }
}

try {
    $handler = new ActivitiesHandler($config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $this->logger->logError("Error in activity endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}