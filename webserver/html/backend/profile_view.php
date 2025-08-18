<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class ProfileHandlerPublic
{
    private PDO $pdo;
    private ?int $userId;
    private string $requestedUsername;
    private array $generalConfig;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private array $session;
    private array $server;
    private array $get;

    public function __construct(
        array $generalConfig,
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

        $this->generalConfig = $generalConfig;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->requestedUsername = trim($this->get['username'] ?? '');
        $this->initSession();
        $this->validateRequest();
        $this->initializeUserData();
        $this->logger->logDebug("Initialized ProfileHandlerPublic for username: {$this->requestedUsername}");
    }

    private function initSession()
    {
        $this->securityHelper->initSecureSession();

        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to profile - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Unauthorized', 401);
        }
    }

    private function validateRequest()
    {
        if (empty($this->requestedUsername)) {
            $this->logger->logError("Empty username requested - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Username is required', 400);
        }

        if (strlen($this->requestedUsername) > $this->generalConfig['user']['MAX_USERNAME_LENGTH'] ||
            strlen($this->requestedUsername) < $this->generalConfig['user']['MIN_USERNAME_LENGTH'] ||
            !preg_match('/' . $this->generalConfig['user']['USERNAME_REGEX'] . '/', $this->requestedUsername)) {
            $this->logger->logError("Invalid username format requested: {$this->requestedUsername}");
            throw new Exception('Invalid username format', 400);
        }

        if (in_array($this->server['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
                $this->logger->logWarning("Invalid CSRF token in profile request - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
                throw new Exception('Invalid request', 403);
            }
        }
    }

    private function initializeUserData()
    {
        try {
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = :username");
            $stmt->execute(['username' => $this->requestedUsername]);
            $user = $stmt->fetch();

            if (!$user) {
                $this->logger->logError("User not found in profile view: {$this->requestedUsername}");
                throw new Exception('Profile not found', 404);
            }

            $this->userId = (int)$user['id'];
        } catch (PDOException $e) {
            $this->logger->logError("Database error during profile initialization: " . $e->getMessage());
            throw new Exception('Database error occurred', 500);
        }
    }

    public function handleRequest()
    {
        try {
            $profileData = $this->getBasicProfileData();
            $stats = $this->getProfileStats();
            $badges = $this->getProfileBadges();

            $response = [
                'success' => true,
                'data' => [
                    'profile' => $this->sanitizeProfileData($profileData),
                    'stats' => $stats,
                    'badges' => $badges
                ]
            ];

            $this->sendResponse($response);
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function getBasicProfileData(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                WITH flag_counts AS (
                    SELECT challenge_template_id, COUNT(*) AS total_flags
                    FROM challenge_flags
                    GROUP BY challenge_template_id
                ),
                user_flags AS (
                    SELECT cc.challenge_template_id, COUNT(DISTINCT cc.flag_id) AS user_flag_count
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                ),
                solved AS (
                    SELECT uf.challenge_template_id
                    FROM user_flags uf
                    JOIN flag_counts fc ON uf.challenge_template_id = fc.challenge_template_id
                    WHERE uf.user_flag_count = fc.total_flags
                ),
                total_points AS (
                    SELECT COALESCE(SUM(cf.points), 0) AS total_points
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                )
                SELECT
                    u.username,
                    u.created_at,
                    u.avatar_url,
                    p.bio,
                    p.github_url,
                    p.twitter_url,
                    p.website_url,
                    (SELECT COUNT(*) FROM solved) AS solved_count,
                    (SELECT total_points FROM total_points) AS total_points
                FROM users u
                LEFT JOIN user_profiles p ON p.user_id = u.id
                WHERE u.id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $profileData = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$profileData) {
                $this->logger->logError("Profile data not found for user ID: {$this->userId}");
                throw new RuntimeException('Profile data not found', 404);
            }

            $rankStmt = $this->pdo->prepare("
                SELECT COUNT(*) + 1 AS user_rank
                FROM (
                    SELECT u.id, COALESCE(SUM(cf.points), 0) AS points
                    FROM users u
                    LEFT JOIN completed_challenges cc ON cc.user_id = u.id
                    LEFT JOIN challenge_flags cf ON cc.flag_id = cf.id
                    GROUP BY u.id
                    HAVING COALESCE(SUM(cf.points), 0) > :user_points
                        OR (COALESCE(SUM(cf.points), 0) = :user_points AND u.id < :user_id)
                ) ranked_users
            ");
            $rankStmt->execute([
                'user_points' => $profileData['total_points'],
                'user_id' => $this->userId
            ]);
            $rankData = $rankStmt->fetch(PDO::FETCH_ASSOC);

            return [
                'username' => $profileData['username'],
                'join_date' => $profileData['created_at'],
                'avatar_url' => $profileData['avatar_url'] ?? '/assets/avatars/default-avatar.png',
                'bio' => $profileData['bio'] ?? '',
                'social_links' => [
                    'github' => $profileData['github_url'] ?? '',
                    'twitter' => $profileData['twitter_url'] ?? '',
                    'website' => $profileData['website_url'] ?? ''
                ],
                'rank' => (int)($rankData['user_rank'] ?? 1),
                'points' => (int)$profileData['total_points'],
                'solved_count' => (int)$profileData['solved_count']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getBasicProfileData: " . $e->getMessage());
            throw new RuntimeException('Could not load profile data', 500);
        }
    }

    private function getProfileStats(): array
    {
        try {
            $successStmt = $this->pdo->prepare("
                WITH flag_counts AS (
                    SELECT challenge_template_id, COUNT(*) AS total_flags
                    FROM challenge_flags
                    GROUP BY challenge_template_id
                ),
                user_flags AS (
                    SELECT cc.challenge_template_id, COUNT(DISTINCT cc.flag_id) AS user_flag_count
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                ),
                solved AS (
                    SELECT uf.challenge_template_id
                    FROM user_flags uf
                    JOIN flag_counts fc ON uf.challenge_template_id = fc.challenge_template_id
                    WHERE uf.user_flag_count = fc.total_flags
                ),
                total_points AS (
                    SELECT COALESCE(SUM(cf.points), 0) AS total_points
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                )
                SELECT
                    (SELECT COUNT(*) FROM solved) AS solved,
                    (SELECT COUNT(DISTINCT challenge_template_id) FROM completed_challenges WHERE user_id = :user_id) AS attempts,
                    (SELECT total_points FROM total_points) AS total_points
            ");
            $successStmt->execute(['user_id' => $this->userId]);
            $successData = $successStmt->fetch(PDO::FETCH_ASSOC);

            if (!$successData) {
                $this->logger->logError("Failed to retrieve stats for user ID: {$this->userId}");
                throw new RuntimeException('Failed to retrieve profile statistics', 500);
            }

            $successRate = 0;
            if ($successData['attempts'] > 0) {
                $successRate = round(($successData['solved'] / $successData['attempts']) * 100);
            }

            $categoryData = $this->getCategoryData();

            return [
                'categories' => array_map('htmlspecialchars', $categoryData['categories']),
                'percentages' => array_map('intval', $categoryData['percentages']),
                'solved_counts' => array_map('intval', $categoryData['solved_counts']),
                'success_rate' => $successRate,
                'total_solved' => (int)$successData['solved'],
                'total_points' => (int)$successData['total_points'],
                'total_attempts' => (int)$successData['attempts']
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProfileStats: " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve profile statistics', 500);
        }
    }

    private function getCategoryData(): array
    {
        try {
            $stmt = $this->pdo->query("SELECT unnest(enum_range(NULL::challenge_category)) AS category ORDER BY category");
            $allCategories = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($allCategories)) {
                $this->logger->logError("No challenge categories found in database");
                throw new RuntimeException('No challenge categories found', 500);
            }

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
                        SELECT COUNT(*) 
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

            return [
                'categories' => $allCategories,
                'percentages' => $percentages,
                'solved_counts' => array_replace(array_fill_keys($allCategories, 0), $solved)
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getCategoryData: " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve category data', 500);
        }
    }

    private function getProfileBadges(): array
    {
        try {
            $badgeStmt = $this->pdo->prepare("
                SELECT b.id, b.name, b.description, b.icon, b.color
                FROM user_badges ub
                JOIN badges b ON b.id = ub.badge_id
                WHERE ub.user_id = :user_id
                ORDER BY b.rarity DESC, ub.earned_at DESC
            ");
            $badgeStmt->execute(['user_id' => $this->userId]);
            $badges = $badgeStmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedBadges = array_map(function ($badge) {
                return [
                    'id' => (int)$badge['id'],
                    'name' => htmlspecialchars($badge['name']),
                    'description' => htmlspecialchars($badge['description']),
                    'icon' => $badge['icon'],
                    'color' => $badge['color']
                ];
            }, $badges);

            $totalStmt = $this->pdo->query("SELECT COUNT(*) AS total FROM badges");
            $totalBadges = (int)$totalStmt->fetch(PDO::FETCH_ASSOC)['total'];

            $earnedCount = count($sanitizedBadges);

            return [
                'badges' => $sanitizedBadges,
                'earned_count' => $earnedCount,
                'total_badges' => $totalBadges
            ];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getProfileBadges: " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve badge information', 500);
        }
    }

    private function sanitizeProfileData(array $data): array
    {
        return [
            'username' => htmlspecialchars($data['username']),
            'join_date' => $data['join_date'],
            'avatar_url' => filter_var($data['avatar_url'], FILTER_SANITIZE_URL),
            'full_name' => htmlspecialchars($data['full_name'] ?? ''),
            'bio' => htmlspecialchars($data['bio'] ?? ''),
            'social_links' => [
                'github' => filter_var($data['social_links']['github'] ?? '', FILTER_SANITIZE_URL),
                'twitter' => filter_var($data['social_links']['twitter'] ?? '', FILTER_SANITIZE_URL),
                'website' => filter_var($data['social_links']['website'] ?? '', FILTER_SANITIZE_URL)
            ],
            'rank' => (int)$data['rank'],
            'points' => (int)$data['points'],
            'solved_count' => (int)$data['solved_count']
        ];
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
            $this->logger->logError("Profile error: " . $e->getMessage());
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
    $handler = new ProfileHandlerPublic($generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $this->logger->logError("Error in profile_view endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}