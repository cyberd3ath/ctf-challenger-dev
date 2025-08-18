<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/challengeHelper.php';
$config = require __DIR__ . '/../config/backend.config.php';

class DashboardHandler
{
    private PDO $pdo;
    private ?int $userId;
    private string $dataType;
    private ?string $range;
    private ?string $view;
    private array $config;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;
    private IChallengeHelper $challengeHelper;

    public function __construct(
        array $config,
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        IChallengeHelper $challengeHelper = new ChallengeHelper()
    )
    {
        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;
        $this->challengeHelper = $challengeHelper;

        $this->config = $config;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->dataType = $_GET['type'] ?? 'all';
        $this->range = $_GET['range'] ?? null;
        $this->view = $_GET['view'] ?? null;
        $this->initSession();
        $this->userId = $_SESSION['user_id'];
        $this->validateRequest();
        $this->logger->logDebug("Initialized DashboardHandler for user ID: {$this->userId}, Data type: {$this->dataType}");
    }

    private function initSession()
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to dashboard - IP: " . $this->logger->anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Unauthorized - Please login', 401);
        }
    }

    private function validateRequest()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token in dashboard - User ID: {$this->userId}, Token: {$csrfToken}");
            throw new Exception('Invalid CSRF token', 403);
        }

        if (!in_array($this->dataType, $this->config['dashboard']['VALID_DATA_TYPES'])) {
            $this->logger->logWarning("Invalid data type requested - User ID: {$this->userId}, Type: {$this->dataType}");
            throw new Exception('Invalid data type requested', 400);
        }
    }

    public function handleRequest()
    {
        try {
            $response = $this->getDashboardData();
            $this->sendResponse($response);
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function getDashboardData(): array
    {
        switch ($this->dataType) {
            case 'user':
                $data = $this->getUserData();
                $this->logger->logDebug("Retrieved user data for user {$this->userId}");
                break;

            case 'progress':
                $data = $this->getProgressData();
                $this->logger->logDebug("Retrieved progress data for user {$this->userId}");
                break;

            case 'category':
                $data = $this->getCategoryData();
                $this->logger->logDebug("Retrieved category data for user {$this->userId}");
                break;

            case 'activity':
                $data = $this->getActivityData();
                $this->logger->logDebug("Retrieved activity data for user {$this->userId}");
                break;

            case 'badges':
                $data = $this->getBadgesData();
                $this->logger->logDebug("Retrieved badges data for user {$this->userId}");
                break;

            case 'active_challenge':
                $data = $this->getActiveChallengeData();
                $this->logger->logDebug("Retrieved active challenge data for user {$this->userId}");
                break;

            case 'challenges':
                $data = $this->getChallengesData();
                $this->logger->logDebug("Retrieved challenges data for user {$this->userId}");
                break;

            case 'timeline':
                $data = $this->getTimelineData($this->range, $this->view);
                $this->logger->logDebug("Retrieved timeline data for user {$this->userId}");
                break;

            case 'news':
                $data = $this->getLatestNews();
                $this->logger->logDebug("Retrieved latest news");
                break;

            default:
                $data = [
                    'user' => $this->getUserData(),
                    'progress' => $this->getProgressData(),
                    'category' => $this->getCategoryData(),
                    'activity' => $this->getActivityData(5),
                    'badges' => $this->getBadgesData(),
                    'active_challenge' => $this->getActiveChallengeData(),
                    'challenges' => $this->getChallengesData(),
                    'timeline' => $this->getTimelineData('week', 'daily'),
                    'news' => $this->getLatestNews()
                ];
                $this->logger->logDebug("Retrieved complete dashboard data for user {$this->userId}");
        }

        return ['success' => true, 'data' => $data];
    }

    private function getUserData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                WITH user_points AS (
                    SELECT COALESCE(SUM(cf.points), 0) AS total
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                ),
                solved_challenges AS (
                    SELECT cc.challenge_template_id
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                    HAVING COUNT(DISTINCT cf.id) = (
                        SELECT COUNT(id) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = cc.challenge_template_id
                    )
                )
                SELECT
                    u.username,
                    (SELECT total FROM user_points) AS total_points,
                    (SELECT COUNT(*) FROM solved_challenges) AS solved_count,
                    (
                        SELECT COUNT(*) + 1
                        FROM (
                            SELECT u2.id, COALESCE(SUM(cf2.points), 0) AS points
                            FROM users u2
                            LEFT JOIN completed_challenges cc2 ON cc2.user_id = u2.id
                            LEFT JOIN challenge_flags cf2 ON cc2.flag_id = cf2.id
                            GROUP BY u2.id
                            HAVING COALESCE(SUM(cf2.points), 0) > (SELECT total FROM user_points)
                            OR (COALESCE(SUM(cf2.points), 0) = (SELECT total FROM user_points) AND u2.id < :user_id)
                        ) ranked_users
                    ) AS user_rank
                FROM users u
                WHERE u.id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$userData) {
                $this->logger->logError("User not found in getUserData: {$this->userId}");
                throw new Exception('User not found', 404);
            }

            return [
                'username' => htmlspecialchars($userData['username']),
                'rank' => (int)$userData['user_rank'],
                'points' => (int)$userData['total_points']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getUserData: " . $e->getMessage());
            throw new Exception('Failed to retrieve user data', 500);
        }
    }

    private function getProgressData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                WITH solved_challenges AS (
                    SELECT cc.challenge_template_id
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                    HAVING COUNT(DISTINCT cf.id) = (
                        SELECT COUNT(id) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = cc.challenge_template_id
                    )
                ),
                failed_attempts AS (
                    SELECT COUNT(DISTINCT challenge_template_id) AS count
                    FROM completed_challenges
                    WHERE user_id = :user_id
                    AND completed_at IS NOT NULL
                    AND challenge_template_id NOT IN (SELECT challenge_template_id FROM solved_challenges)
                )
                SELECT
                    (SELECT COUNT(*) FROM solved_challenges) AS solved_count,
                    (SELECT count FROM failed_attempts) AS failed_count,
                    COUNT(DISTINCT challenge_template_id) AS total_attempts,
                    AVG(
                        CASE
                            WHEN completed_at > started_at
                            THEN EXTRACT(EPOCH FROM (completed_at - started_at))
                            ELSE NULL
                        END
                    ) AS avg_time_seconds
                FROM completed_challenges
                WHERE user_id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $progress = $stmt->fetch(PDO::FETCH_ASSOC);

            $stmt = $this->pdo->prepare("SELECT COUNT(*) AS total_challenges FROM challenge_templates WHERE is_active = true");
            $stmt->execute();
            $total = $stmt->fetch(PDO::FETCH_ASSOC);

            $solved = (int)($progress['solved_count'] ?? 0);
            $failed = (int)($progress['failed_count'] ?? 0);
            $unsolved = max(0, (int)($total['total_challenges'] ?? 0) - $solved);

            $avgTimeSeconds = isset($progress['avg_time_seconds'])
                ? max(0, (float)$progress['avg_time_seconds'])
                : 0;

            $successRate = isset($progress['total_attempts']) && $progress['total_attempts'] > 0
                ? round(($solved / $progress['total_attempts']) * 100)
                : 0;

            return [
                'solved' => $solved,
                'failed' => $failed,
                'unsolved' => $unsolved,
                'success_rate' => $successRate,
                'avg_time' => $this->formatTime($avgTimeSeconds)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProgressData: " . $e->getMessage());
            throw new Exception('Failed to retrieve progress data', 500);
        }
    }

    private function formatTime(float $seconds): string
    {
        if ($seconds < 60) {
            return round($seconds) . 's';
        } elseif ($seconds < 3600) {
            return round($seconds / 60) . 'm';
        } elseif ($seconds < 86400) {
            return round($seconds / 3600, 1) . 'h';
        }
        return round($seconds / 86400, 1) . 'd';
    }

    private function getCategoryData(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT unnest(enum_range(NULL::challenge_category)) AS category 
                ORDER BY category
            ");
            $allCategories = $stmt->fetchAll(PDO::FETCH_COLUMN);

            $totals = [];
            $stmt = $this->pdo->query("
                SELECT category, COUNT(*) as total 
                FROM challenge_templates 
                WHERE is_active = true
                GROUP BY category
            ");
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $totals[$row['category']] = (int)$row['total'];
            }

            $stmt = $this->pdo->prepare("
                WITH solved_challenges AS (
                    SELECT cc.challenge_template_id
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                    HAVING COUNT(DISTINCT cf.id) = (
                        SELECT COUNT(id) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = cc.challenge_template_id
                    )
                )
                SELECT ct.category, COUNT(sc.challenge_template_id) as solved
                FROM solved_challenges sc
                JOIN challenge_templates ct ON ct.id = sc.challenge_template_id
                GROUP BY ct.category
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $solved = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

            $percentages = [];
            foreach ($allCategories as $category) {
                $total = $totals[$category] ?? 0;
                $solvedCount = $solved[$category] ?? 0;
                $percentages[$category] = $total > 0 ? round(($solvedCount / $total) * 100) : 0;
            }

            return ['percentages' => $percentages];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getCategoryData: " . $e->getMessage());
            throw new Exception('Failed to retrieve category data', 500);
        }
    }

    private function getActivityData(int $limit = 5): array
    {
        try {
            $stmt = $this->pdo->prepare("
                WITH user_completed_flags AS (
                    SELECT 
                        cc.challenge_template_id, 
                        cf.id AS flag_id,
                        cf.points
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                ),
                solved_challenges AS (
                    SELECT 
                        ucf.challenge_template_id, 
                        MAX(cc.completed_at) as completed_at,
                        SUM(ucf.points) as total_points
                    FROM user_completed_flags ucf
                    JOIN completed_challenges cc ON cc.flag_id = ucf.flag_id AND cc.user_id = :user_id
                    GROUP BY ucf.challenge_template_id
                    HAVING COUNT(DISTINCT ucf.flag_id) = (
                        SELECT COUNT(id) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = ucf.challenge_template_id
                    )
                ),
                challenge_attempts AS (
                    SELECT
                        cc.challenge_template_id,
                        COUNT(cc.id) AS attempts,
                        MIN(cc.started_at) AS started_at,
                        MAX(cc.completed_at) AS completed_at,
                        BOOL_OR(cc.completed_at IS NOT NULL) AS has_completed_attempt,
                        SUM(CASE WHEN cc.flag_id IS NOT NULL THEN 
                            (SELECT points FROM challenge_flags WHERE id = cc.flag_id)
                        ELSE 0 END) AS earned_points
                    FROM completed_challenges cc
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                )
                SELECT
                    ct.id AS challenge_id,
                    ct.name AS challenge_name,
                    ct.category,
                    sc.total_points AS solved_points,
                    ca.earned_points AS current_points,
                    sc.completed_at IS NOT NULL AS solved,
                    ca.attempts,
                    ca.started_at,
                    ca.completed_at,
                    CASE
                        WHEN sc.completed_at IS NOT NULL THEN 'solved'
                        WHEN ca.has_completed_attempt THEN 'failed'
                        ELSE 'active'
                    END AS status,
                    CASE
                        WHEN sc.completed_at IS NOT NULL THEN
                            CASE
                                WHEN EXTRACT(EPOCH FROM (NOW() - sc.completed_at)) / 3600 < 24 THEN 
                                    EXTRACT(HOUR FROM (NOW() - sc.completed_at)) || ' hours ago'
                                ELSE 
                                    EXTRACT(DAY FROM (NOW() - sc.completed_at)) || ' days ago'
                            END
                        WHEN ca.completed_at IS NOT NULL THEN
                            CASE
                                WHEN EXTRACT(EPOCH FROM (NOW() - ca.completed_at)) / 3600 < 24 THEN 
                                    'Failed ' || EXTRACT(HOUR FROM (NOW() - ca.completed_at)) || ' hours ago'
                                ELSE 
                                    'Failed ' || EXTRACT(DAY FROM (NOW() - ca.completed_at)) || ' days ago'
                            END
                        ELSE
                            CASE
                                WHEN EXTRACT(EPOCH FROM (NOW() - ca.started_at)) / 3600 < 24 THEN 
                                    'Started ' || EXTRACT(HOUR FROM (NOW() - ca.started_at)) || ' hours ago'
                                ELSE 
                                    'Started ' || EXTRACT(DAY FROM (NOW() - ca.started_at)) || ' days ago'
                            END
                    END AS time_ago
                FROM challenge_templates ct
                JOIN challenge_attempts ca ON ca.challenge_template_id = ct.id
                LEFT JOIN solved_challenges sc ON sc.challenge_template_id = ct.id
                WHERE EXISTS (
                    SELECT 1 FROM completed_challenges 
                    WHERE user_id = :user_id AND challenge_template_id = ct.id
                )
                ORDER BY COALESCE(sc.completed_at, ca.completed_at, ca.started_at) DESC
                LIMIT :limit
            ");

            $stmt->bindValue(':user_id', $this->userId, PDO::PARAM_INT);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();

            $activities = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $points = $row['solved']
                    ? (int)$row['solved_points']
                    : (int)$row['current_points'];

                $activities[] = [
                    'challenge_id' => (int)$row['challenge_id'],
                    'challenge' => htmlspecialchars($row['challenge_name']),
                    'category' => htmlspecialchars($row['category']),
                    'points' => $points,
                    'status' => $row['status'],
                    'attempts' => (int)$row['attempts'],
                    'time_ago' => $row['time_ago'],
                    'started_at' => $row['started_at']
                ];
            }

            return $activities;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getActivityData: " . $e->getMessage());
            throw new Exception('Failed to retrieve activity data', 500);
        }
    }

    private function getBadgesData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT b.id, b.name, b.description, b.icon, b.color
                FROM user_badges ub
                JOIN badges b ON b.id = ub.badge_id
                WHERE ub.user_id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $badges = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedBadges = [];
            foreach ($badges as $badge) {
                $sanitizedBadges[] = [
                    'id' => (int)$badge['id'],
                    'name' => htmlspecialchars($badge['name']),
                    'description' => htmlspecialchars($badge['description']),
                    'icon' => htmlspecialchars($badge['icon']),
                    'color' => htmlspecialchars($badge['color'])
                ];
            }

            $stmt = $this->pdo->prepare("
                WITH user_completed_flags AS (
                    SELECT DISTINCT challenge_template_id, flag_id
                    FROM completed_challenges
                    WHERE user_id = :user_id
                ),
                challenge_total_flags AS (
                    SELECT challenge_template_id, COUNT(*) as total_flags
                    FROM challenge_flags
                    GROUP BY challenge_template_id
                ),
                user_solved_challenges AS (
                    SELECT ctf.challenge_template_id
                    FROM challenge_total_flags ctf
                    JOIN (
                        SELECT challenge_template_id, COUNT(DISTINCT flag_id) as completed_flags
                        FROM user_completed_flags
                        GROUP BY challenge_template_id
                    ) ucf ON ctf.challenge_template_id = ucf.challenge_template_id
                    WHERE ctf.total_flags = ucf.completed_flags
                )
                SELECT
                    COUNT(*) AS solved_count,
                    (SELECT COUNT(*) FROM badges) AS total_badges,
                    (SELECT COUNT(*) FROM user_badges WHERE user_id = :user_id) AS earned_badges
                FROM user_solved_challenges
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $progress = $stmt->fetch(PDO::FETCH_ASSOC);

            $nextBadgeProgress = isset($progress['total_badges']) && $progress['total_badges'] > 0
                ? round(
                    ($progress['earned_badges'] /
                        ($progress['earned_badges'] == $progress['total_badges']
                            ? $progress['total_badges']
                            : max(1, $progress['total_badges'] - 1)
                        )
                    ) * 100
                )
                : 0;

            return [
                'earned' => $sanitizedBadges,
                'next_badge' => [
                    'name' => 'Master Hacker',
                    'progress' => $nextBadgeProgress,
                    'requirements' => 'Earn all badges',
                    'solved_count' => (int)($progress['solved_count'] ?? 0)
                ]
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getBadgesData: " . $e->getMessage());
            throw new Exception('Failed to retrieve badges data', 500);
        }
    }

    private function getChallengesData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                WITH user_solved_challenges AS (
                    SELECT cc.challenge_template_id
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                    HAVING COUNT(DISTINCT cf.id) = (
                        SELECT COUNT(*) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = cc.challenge_template_id
                    )
                ),
                global_solved_counts AS (
                    SELECT 
                        cc.challenge_template_id,
                        COUNT(DISTINCT cc.user_id) AS solved_count
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    GROUP BY cc.challenge_template_id
                    HAVING COUNT(DISTINCT cf.id) = (
                        SELECT COUNT(*) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = cc.challenge_template_id
                    )
                ),
                attempted_counts AS (
                    SELECT 
                        challenge_template_id,
                        COUNT(DISTINCT user_id) AS attempted_count
                    FROM completed_challenges
                    GROUP BY challenge_template_id
                )
                SELECT
                    ct.id,
                    ct.name,
                    ct.category,
                    (SELECT SUM(points) FROM challenge_flags WHERE challenge_template_id = ct.id) AS points,
                    ct.difficulty,
                    COALESCE(gsc.solved_count, 0) AS solved_count,
                    COALESCE(ac.attempted_count, 0) AS attempted_count
                FROM challenge_templates ct
                LEFT JOIN global_solved_counts gsc ON gsc.challenge_template_id = ct.id
                LEFT JOIN attempted_counts ac ON ac.challenge_template_id = ct.id
                WHERE NOT EXISTS (
                    SELECT 1 FROM user_solved_challenges usc
                    WHERE usc.challenge_template_id = ct.id
                )
                ORDER BY
                    CASE ct.difficulty
                        WHEN 'easy' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'hard' THEN 3
                        ELSE 0
                    END,
                    COALESCE(gsc.solved_count, 0)::float / NULLIF(COALESCE(ac.attempted_count, 0), 0) DESC
                LIMIT 5
            ");

            $stmt->execute(['user_id' => $this->userId]);

            $challenges = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $attempted = (int)($row['attempted_count'] ?? 0);
                $solved = (int)($row['solved_count'] ?? 0);
                $successRate = $attempted > 0 ? round(($solved / $attempted) * 100) : 0;

                $challenges[] = [
                    'id' => (int)$row['id'],
                    'name' => htmlspecialchars($row['name']),
                    'category' => htmlspecialchars($row['category']),
                    'points' => (int)$row['points'],
                    'difficulty' => htmlspecialchars($row['difficulty']),
                    'success_rate' => $successRate . '%'
                ];
            }

            return $challenges;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getChallengesData: " . $e->getMessage());
            throw new Exception('Failed to retrieve challenges data', 500);
        }
    }

    private function getTimelineData(string $range = 'week', string $viewType = 'daily'): array
    {
        try {
            $endDate = new DateTime();
            $startDate = clone $endDate;

            switch ($range) {
                case 'week':
                    $interval = "'1 day'";
                    $dateFormat = 'YYYY-MM-DD';
                    $startDate->modify('-6 days');
                    $labelFormat = 'D';
                    break;
                case 'month':
                    $interval = "'1 day'";
                    $dateFormat = 'YYYY-MM-DD';
                    $startDate->modify('-29 days');
                    $labelFormat = 'j M';
                    break;
                case 'year':
                    $interval = "'1 month'";
                    $dateFormat = 'YYYY-MM';
                    $startDate->modify('-11 months');
                    $labelFormat = 'M';
                    break;
                default:
                    throw new Exception('Invalid time range specified', 400);
            }

            if (!in_array($viewType, ['daily', 'cumulative'])) {
                throw new Exception('Invalid timeline view type specified', 400);
            }

            $sql = "
                WITH date_series AS (
                    SELECT generate_series(
                        :start_date::timestamp,
                        :end_date::timestamp,
                        INTERVAL $interval
                    )::date AS date
                ),
                flag_submissions AS (
                    SELECT 
                        cc.id,
                        cc.challenge_template_id,
                        cf.points,
                        TO_CHAR(cc.completed_at, :date_format) AS date_group,
                        cc.completed_at
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    AND cc.completed_at IS NOT NULL
                ),
                daily_points AS (
                    SELECT
                        ds.date,
                        TO_CHAR(ds.date, :date_format) AS date_group,
                        COALESCE(SUM(fs.points), 0) AS points_sum,
                        COUNT(DISTINCT fs.challenge_template_id) AS challenge_count,
                        STRING_AGG(DISTINCT CONCAT(
                            (SELECT name FROM challenge_templates WHERE id = fs.challenge_template_id),
                            '|',
                            (SELECT category FROM challenge_templates WHERE id = fs.challenge_template_id),
                            '|',
                            fs.points
                        ), ',') AS challenge_details
                    FROM date_series ds
                    LEFT JOIN flag_submissions fs ON TO_CHAR(ds.date, :date_format) = fs.date_group
                    GROUP BY ds.date, TO_CHAR(ds.date, :date_format)
                    ORDER BY ds.date
                )
                SELECT 
                    date_group,
                    points_sum,
                    challenge_count,
                    challenge_details
                FROM daily_points
            ";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([
                'user_id' => $this->userId,
                'start_date' => $startDate->format('Y-m-d'),
                'end_date' => $endDate->format('Y-m-d'),
                'date_format' => $dateFormat
            ]);

            $labels = [];
            $points = [];
            $challenges = [];
            $details = [];

            $currentDate = clone $startDate;
            while ($currentDate <= $endDate) {
                $formattedDate = $currentDate->format($range === 'year' ? 'Y-m' : 'Y-m-d');
                $labels[] = $currentDate->format($labelFormat);
                $points[$formattedDate] = 0;
                $challenges[$formattedDate] = 0;
                $details[$formattedDate] = [];

                if ($range === 'week' || $range === 'month') {
                    $currentDate->modify('+1 day');
                } else {
                    $currentDate->modify('+1 month');
                }
            }

            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                if (isset($points[$row['date_group']])) {
                    $points[$row['date_group']] = (int)$row['points_sum'];
                    $challenges[$row['date_group']] = (int)$row['challenge_count'];

                    if ($row['challenge_details']) {
                        foreach (explode(',', $row['challenge_details']) as $detail) {
                            if (!empty($detail)) {
                                list($name, $category, $pointsVal) = explode('|', $detail);
                                $details[$row['date_group']][] = [
                                    'name' => htmlspecialchars($name),
                                    'category' => htmlspecialchars($category),
                                    'points' => (int)$pointsVal
                                ];
                            }
                        }
                    }
                }
            }

            if ($viewType === 'cumulative') {
                $points = $this->accumulateArray(array_values($points));
                $challenges = $this->accumulateArray(array_values($challenges));
            } else {
                $points = array_values($points);
                $challenges = array_values($challenges);
            }

            return [
                'labels' => $labels,
                'points' => $points,
                'challenges' => $challenges,
                'details' => array_values($details)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getTimelineData: " . $e->getMessage());
            throw new Exception('Failed to retrieve timeline data', 500);
        }
    }

    private function getLatestNews(): array
    {
        try {
            $stmt = $this->pdo->query("
                SELECT 
                    id,
                    title,
                    short_description,
                    importance,
                    category,
                    author,
                    TO_CHAR(created_at, 'YYYY-MM-DD') AS created_at
                FROM announcements
                ORDER BY created_at DESC
                LIMIT 3
            ");
            $news = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedNews = [];
            foreach ($news as $item) {
                $sanitizedNews[] = [
                    'id' => (int)$item['id'],
                    'title' => htmlspecialchars($item['title']),
                    'short_description' => htmlspecialchars($item['short_description']),
                    'importance' => htmlspecialchars($item['importance']),
                    'category' => htmlspecialchars($item['category']),
                    'author' => htmlspecialchars($item['author']),
                    'created_at' => $item['created_at']
                ];
            }

            return $sanitizedNews;
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getLatestNews: " . $e->getMessage());
            throw new Exception('Failed to retrieve latest news', 500);
        }
    }

    private function getActiveChallengeData(): ?array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT running_challenge 
                FROM users 
                WHERE id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$result || !$result['running_challenge']) {
                return null;
            }

            $runningChallengeId = $result['running_challenge'];

            $stmt = $this->pdo->prepare("
                SELECT challenge_template_id FROM challenges WHERE id = :running_challenge_id
            ");
            $stmt->execute(['running_challenge_id' => $runningChallengeId]);
            $challenge_template_id = (int)$stmt->fetchColumn();

            $elapsedSeconds = $this->challengeHelper->getElapsedSecondsForChallenge($this->pdo,$this->userId,$challenge_template_id);

            $stmt = $this->pdo->prepare("
                SELECT 
                    ct.id,
                    ct.name,
                    ct.category,
                    ct.difficulty,
                    (SELECT SUM(points) FROM challenge_flags WHERE challenge_template_id = ct.id) AS points,
                    cc.started_at AS current_attempt_started_at,
                    cc.id AS completed_challenge_id
                FROM challenge_templates ct
                LEFT JOIN completed_challenges cc 
                    ON cc.user_id = :user_id 
                    AND cc.challenge_template_id = ct.id 
                    AND cc.completed_at IS NULL
                WHERE ct.id = :challenge_template_id
                LIMIT 1
            ");
            $stmt->execute([
                'challenge_template_id' => $challenge_template_id,
                'user_id' => $this->userId
            ]);

            $challenge = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$challenge) {
                $this->logger->logError("Challenge details not found for running challenge ID: $runningChallengeId");
                return null;
            }

            return [
                'id' => (int)$challenge['id'],
                'name' => htmlspecialchars($challenge['name']),
                'category' => htmlspecialchars($challenge['category']),
                'difficulty' => htmlspecialchars($challenge['difficulty']),
                'points' => (int)$challenge['points'],
                'started_at' => $challenge['current_attempt_started_at'],
                'elapsedSeconds' => $elapsedSeconds,
                'isSolved' => $this->challengeHelper->isChallengeSolved($this->pdo, $this->userId, $challenge['id']),
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getActiveChallengeData: " . $e->getMessage());
            throw new Exception('Failed to retrieve active challenge data', 500);
        }
    }

    private function accumulateArray(array $input): array
    {
        $output = [];
        $sum = 0;
        foreach ($input as $value) {
            $sum += $value;
            $output[] = $sum;
        }
        return $output;
    }

    private function sendResponse(array $response)
    {
        echo json_encode($response);
    }

    private function handleError(Exception $e)
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $e->getMessage();

        if ($errorCode === 401) {
            session_unset();
            session_destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
        }

        if ($errorCode >= 500) {
            $errorMessage = 'An internal server error occurred';
            $this->logger->logError("Internal error : " . $e->getMessage());
        } else {
            $this->logger->logError("Dashboard error: " . $e->getMessage());
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
    $handler = new DashboardHandler($config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $this->logger->logError("Error in dashboard endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}