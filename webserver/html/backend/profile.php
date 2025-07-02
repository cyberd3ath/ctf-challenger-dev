<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/auth.php';
$config = require __DIR__ . '/../config/backend.config.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class ProfileHandler
{
    private PDO $pdo;
    private ?int $userId;
    private string $requestMethod;
    private array $config;
    private array $generalConfig;

    public function __construct(array $config, array $generalConfig)
    {
        $this->config = $config;
        $this->generalConfig = $generalConfig;
        $this->pdo = getPDO();
        $this->initSession();
        $this->validateSession();
        $this->userId = (int)$_SESSION['user_id'];
        $this->requestMethod = $_SERVER['REQUEST_METHOD'];
        logDebug("Initialized ProfileHandler for user ID: {$this->userId}");
    }

    private function initSession(): void
    {
        init_secure_session();
    }

    private function validateSession(): void
    {
        if (!validate_session()) {
            logWarning("Unauthorized access attempt to profile - IP: {$_SERVER['REMOTE_ADDR']}");
            throw new Exception('Unauthorized - Please login', 401);
        }

        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning("Invalid CSRF token in profile request - User ID: {$this->userId}, Token: {$csrfToken}");
            throw new Exception('Invalid CSRF token', 403);
        }
    }

    public function handleRequest(): void
    {
        try {
            switch ($this->requestMethod) {
                case 'GET':
                    $this->handleGetRequest();
                    break;
                case 'POST':
                    $this->handlePostRequest();
                    break;
                case 'DELETE':
                    $this->handleDeleteRequest();
                    break;
                default:
                    logWarning("Invalid method in profile request - Method: {$this->requestMethod}, User ID: {$this->userId}");
                    throw new Exception('Method not allowed', 405);
            }
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function handleGetRequest(): void
    {
        $dataType = $_GET['type'] ?? 'full';
        $response = [];

        if (!in_array($dataType, ['basic', 'stats', 'badges', 'activity', 'full'])) {
            logWarning("Invalid data type requested - Type: {$dataType}, User ID: {$this->userId}");
            throw new Exception('Invalid data type requested', 400);
        }

        switch ($dataType) {
            case 'basic':
                $response = $this->getBasicProfileData();
                break;
            case 'stats':
                $response = $this->getProfileStats();
                break;
            case 'badges':
                $response = $this->getProfileBadges();
                break;
            case 'activity':
                $response = $this->getRecentActivity();
                break;
            default:
                $response = [
                    'basic' => $this->getBasicProfileData(),
                    'stats' => $this->getProfileStats(),
                    'badges' => $this->getProfileBadges(),
                    'activity' => $this->getRecentActivity()
                ];
        }
        $this->sendResponse(['success' => true, 'data' => $response]);
    }

    private function handlePostRequest(): void
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $isJson = strpos($contentType, 'application/json') !== false;
        $data = [];

        if ($isJson) {
            $json = file_get_contents('php://input');
            $data = json_decode($json, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                logWarning("Invalid JSON in profile update - User ID: {$this->userId}");
                throw new Exception('Invalid JSON data', 400);
            }
        } else {
            $data = $_POST;
        }

        $action = $data['action'] ?? '';
        switch ($action) {
            case 'update_username':
                $this->validateUsername($data['username'] ?? '');
                $this->updateUsername($data['username']);
                break;
            case 'update_email':
                $this->validateEmail($data['email'] ?? '');
                $this->updateEmail($data['email']);
                break;
            case 'update_full_name':
                $this->validateFullName($data['full_name'] ?? '');
                $this->updateFullName($data['full_name']);
                break;
            case 'update_bio':
                $this->validateBio($data['bio'] ?? '');
                $this->updateBio($data['bio']);
                break;
            case 'update_social':
                $this->validateSocialLinks([
                    'github' => $data['github'] ?? '',
                    'twitter' => $data['twitter'] ?? '',
                    'website' => $data['website'] ?? ''
                ]);
                $this->updateSocialLinks([
                    'github' => $data['github'],
                    'twitter' => $data['twitter'],
                    'website' => $data['website']
                ]);
                break;
            case 'upload_avatar':
                $this->handleAvatarUpload();
                break;
            case 'update_avatar':
                $this->validateAvatarSelection($data['avatar'] ?? '');
                $this->handleAvatarUpdate();
                break;
            case 'change_password':
                $this->validatePasswordChange(
                    $data['current_password'] ?? '',
                    $data['new_password'] ?? ''
                );
                $this->changePassword($data['current_password'], $data['new_password']);
                break;
            case 'get_vpn_config':
                $this->handleVpnConfigDownload();
                break;
            default:
                logWarning("Invalid action in profile update - Action: {$action}, User ID: {$this->userId}");
                throw new Exception('Invalid action specified', 400);
        }
    }

    private function validateUsername(string $username): void
    {
        if (empty($username)) {
            throw new Exception('Username cannot be empty', 400);
        }
        if (strlen($username) < $this->generalConfig['user']['MIN_USERNAME_LENGTH'] || strlen($username) > $this->generalConfig['user']['MAX_USERNAME_LENGTH']) {
            throw new Exception(sprintf('Username must be between %d and %d characters',
                $this->generalConfig['user']['MIN_USERNAME_LENGTH'], $this->generalConfig['user']['MAX_USERNAME_LENGTH']), 400);
        }
        if (!preg_match('/' . $this->generalConfig['user']['USERNAME_REGEX'] . '/', $username)) {
            throw new Exception('Username can only contain letters, numbers and underscores', 400);
        }
    }

    private function validateEmail(string $email): void
    {
        if (empty($email)) {
            throw new Exception('Email cannot be empty', 400);
        }
        if (strlen($email) > $this->generalConfig['user']['MAX_EMAIL_LENGTH']) {
            throw new Exception('Email is too long', 400);
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception('Invalid email format', 400);
        }
    }

    private function validateFullName(string $fullName): void
    {
        if (empty($fullName)) {
            throw new Exception('Full name cannot be empty', 400);
        }
        if (strlen($fullName) < $this->generalConfig['user']['MIN_FULL_NAME_LENGTH'] || strlen($fullName) > $this->generalConfig['user']['MAX_FULL_NAME_LENGTH']) {
            throw new Exception(sprintf('Name must be between %d and %d characters',
                $this->generalConfig['user']['MIN_FULL_NAME_LENGTH'], $this->generalConfig['user']['MAX_FULL_NAME_LENGTH']), 400);
        }
        if (!preg_match('/' . $this->generalConfig['user']['FULL_NAME_REGEX'] . '/u', $fullName)) {
            throw new Exception('Name contains invalid characters. Name must include at least a first and last name, starting with capital letters.', 400);
        }
    }

    private function validateBio(string $bio): void
    {
        if (strlen($bio) > $this->generalConfig['user']['MAX_BIO_LENGTH']) {
            throw new Exception(sprintf('Bio cannot exceed %d characters', $this->generalConfig['user']['MAX_BIO_LENGTH']), 400);
        }
    }

    private function validateSocialLinks(array $links): void
    {
        foreach ($links as $type => $url) {
            $url = trim($url);

            if (!empty($url) && strlen($url) > $this->generalConfig['user']['MAX_SOCIAL_URL_LENGTH']) {
                throw new Exception(sprintf('%s URL is too long', ucfirst($type)), 400);
            }

            if (empty($url)) {
                continue;
            }

            if (!filter_var($url, FILTER_VALIDATE_URL)) {
                throw new Exception(sprintf('Invalid %s URL', $type), 400);
            }

            switch ($type) {
                case 'github':
                    if (!preg_match('/' . $this->generalConfig['user']['GITHUB_REGEX'] . '/', $url)) {
                        throw new Exception('GitHub URL must be in the format https://github.com/username', 400);
                    }
                    break;

                case 'twitter':
                    if (!preg_match('/' . $this->generalConfig['user']['TWITTER_REGEX'] . '/', $url)) {
                        throw new Exception('Twitter URL must be in the format https://twitter.com/username or https://x.com/username', 400);
                    }
                    break;

                case 'website':
                    break;

                default:
                    throw new Exception(sprintf('Unknown social link type: %s', $type), 400);
            }
        }
    }

    private function validatePasswordChange(string $currentPassword, string $newPassword): void
    {
        if (empty($currentPassword) || empty($newPassword)) {
            throw new Exception('Both current and new password are required', 400);
        }
        if (strlen($newPassword) < $this->generalConfig['user']['MIN_PASSWORD_LENGTH']) {
            throw new Exception(sprintf('Password must be at least %d characters', $this->generalConfig['user']['MIN_PASSWORD_LENGTH']), 400);
        }
        if (strlen($newPassword) > $this->generalConfig['user']['MAX_PASSWORD_LENGTH']) {
            throw new Exception(sprintf('Password cannot exceed %d characters', $this->generalConfig['user']['MAX_PASSWORD_LENGTH']), 400);
        }
    }

    private function validateAvatarSelection(string $avatar): void
    {
        $allowedAvatars = ['avatar1', 'avatar2', 'avatar3'];
        if (!in_array($avatar, $allowedAvatars)) {
            throw new Exception('Invalid avatar selection', 400);
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
                    u.email,
                    u.created_at,
                    u.last_login,
                    u.avatar_url,
                    p.full_name,
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
                logError("Profile not found - User ID: {$this->userId}");
                throw new RuntimeException('User profile not available', 404);
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

            $lastLogin = 'Never';
            if ($profileData['last_login'] && $profileData['last_login'] !== '0000-00-00 00:00:00') {
                try {
                    $lastLogin = (new DateTime($profileData['last_login']))->format('F j, Y \a\t g:i A');
                } catch (Exception $e) {
                    logError("Invalid last login date format - User ID: {$this->userId}, Date: {$profileData['last_login']}");
                    $lastLogin = 'Unknown';
                }
            }

            return [
                'username' => htmlspecialchars($profileData['username'], ENT_QUOTES, 'UTF-8'),
                'email' => filter_var($profileData['email'], FILTER_SANITIZE_EMAIL),
                'join_date' => $profileData['created_at'],
                'last_login' => $lastLogin,
                'avatar_url' => filter_var($profileData['avatar_url'] ?? '/assets/avatars/default-avatar.png', FILTER_SANITIZE_URL),
                'full_name' => htmlspecialchars($profileData['full_name'] ?? '', ENT_QUOTES, 'UTF-8'),
                'bio' => htmlspecialchars($profileData['bio'] ?? '', ENT_QUOTES, 'UTF-8'),
                'social_links' => [
                    'github' => filter_var($profileData['github_url'] ?? '', FILTER_SANITIZE_URL),
                    'twitter' => filter_var($profileData['twitter_url'] ?? '', FILTER_SANITIZE_URL),
                    'website' => filter_var($profileData['website_url'] ?? '', FILTER_SANITIZE_URL)
                ],
                'rank' => (int)($rankData['user_rank'] ?? 1),
                'points' => (int)$profileData['total_points'],
                'solved_count' => (int)$profileData['solved_count']
            ];

        } catch (PDOException $e) {
            logError("Database error in getBasicProfileData - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve profile data', 500);
        }
    }


    private function getProfileStats(): array
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
                    (SELECT COUNT(*) FROM solved) AS solved,
                    (SELECT COUNT(DISTINCT challenge_template_id) FROM completed_challenges WHERE user_id = :user_id) AS attempts,
                    (SELECT total_points FROM total_points) AS total_points
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $statsData = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$statsData) {
                logError("Failed to retrieve profile stats - User ID: {$this->userId}");
                throw new RuntimeException('Failed to retrieve profile statistics', 500);
            }

            $successRate = 0;
            if ($statsData['attempts'] > 0) {
                $successRate = round(($statsData['solved'] / $statsData['attempts']) * 100);
            }

            $categoryData = $this->getCategoryData();

            return [
                'categories' => array_map('htmlspecialchars', $categoryData['categories']),
                'percentages' => array_map('intval', $categoryData['percentages']),
                'solved_counts' => array_map('intval', $categoryData['solved_counts']),
                'success_rate' => $successRate,
                'total_solved' => (int)$statsData['solved'],
                'total_points' => (int)$statsData['total_points'],
                'total_attempts' => (int)$statsData['attempts']
            ];

        } catch (PDOException $e) {
            logError("Database error in getProfileStats - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve profile statistics', 500);
        }
    }

    private function getProfileBadges(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT b.id, b.name, b.description, b.icon, b.color
                FROM user_badges ub
                JOIN badges b ON b.id = ub.badge_id
                WHERE ub.user_id = :user_id
                ORDER BY b.rarity DESC, ub.earned_at DESC
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $badges = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $sanitizedBadges = array_map(function ($badge) {
                return [
                    'id' => (int)$badge['id'],
                    'name' => htmlspecialchars($badge['name'], ENT_QUOTES, 'UTF-8'),
                    'description' => htmlspecialchars($badge['description'], ENT_QUOTES, 'UTF-8'),
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
            logError("Database error in getProfileBadges - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve badge information', 500);
        }
    }

    private function getRecentActivity(int $limit = 5): array
    {
        try {
            if ($limit < 1 || $limit > 50) {
                $limit = 5;
            }

            $stmt = $this->pdo->prepare("
                WITH solved_challenges AS (
                    SELECT cc.challenge_template_id, MAX(cc.completed_at) as completed_at
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
                challenge_attempts AS (
                    SELECT
                        cc.challenge_template_id,
                        COUNT(cc.id) AS attempts,
                        MIN(cc.started_at) AS started_at,
                        MAX(cc.completed_at) AS completed_at,
                        BOOL_OR(cc.completed_at IS NOT NULL) AS has_completed_attempt
                    FROM completed_challenges cc
                    WHERE cc.user_id = :user_id
                    GROUP BY cc.challenge_template_id
                )
                SELECT
                    ct.id AS challenge_id,
                    ct.name AS challenge_name,
                    ct.category,
                    (SELECT MAX(cf.points) FROM challenge_flags cf WHERE cf.challenge_template_id = ct.id) AS points,
                    sc.completed_at IS NOT NULL AS solved,
                    ca.attempts,
                    ca.started_at,
                    ca.completed_at,
                    CASE
                        WHEN sc.completed_at IS NOT NULL THEN 'solved'
                        WHEN ca.has_completed_attempt THEN 'failed'
                        ELSE 'started'
                    END AS status,
                    CASE
                        WHEN sc.completed_at IS NOT NULL THEN
                            CASE
                                WHEN EXTRACT(HOUR FROM (NOW() - sc.completed_at)) < 24
                                THEN EXTRACT(HOUR FROM (NOW() - sc.completed_at)) || ' hours ago'
                                ELSE EXTRACT(DAY FROM (NOW() - sc.completed_at)) || ' days ago'
                            END
                        WHEN ca.completed_at IS NOT NULL THEN
                            CASE
                                WHEN EXTRACT(HOUR FROM (NOW() - ca.completed_at)) < 24
                                THEN 'Failed ' || EXTRACT(HOUR FROM (NOW() - ca.completed_at)) || ' hours ago'
                                ELSE 'Failed ' || EXTRACT(DAY FROM (NOW() - ca.completed_at)) || ' days ago'
                            END
                        ELSE
                            CASE
                                WHEN EXTRACT(HOUR FROM (NOW() - ca.started_at)) < 24
                                THEN 'Started ' || EXTRACT(HOUR FROM (NOW() - ca.started_at)) || ' hours ago'
                                ELSE 'Started ' || EXTRACT(DAY FROM (NOW() - ca.started_at)) || ' days ago'
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
                $activities[] = [
                    'challenge_id' => (int)$row['challenge_id'],
                    'challenge_name' => htmlspecialchars($row['challenge_name'], ENT_QUOTES, 'UTF-8'),
                    'category' => htmlspecialchars($row['category'], ENT_QUOTES, 'UTF-8'),
                    'points' => (int)$row['points'],
                    'status' => $row['status'],
                    'attempts' => (int)$row['attempts'],
                    'time_ago' => $row['time_ago'],
                    'started_at' => $row['started_at'],
                    'completed_at' => $row['completed_at']
                ];
            }

            return $activities;

        } catch (PDOException $e) {
            logError("Database error in getRecentActivity - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve recent activity', 500);
        }
    }

    private function updateUsername(string $newUsername): void
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = :username AND id != :user_id");
            $stmt->execute(['username' => $newUsername, 'user_id' => $this->userId]);
            if ($stmt->fetch()) {
                logWarning("Username already taken - Username: {$newUsername}, User ID: {$this->userId}");
                throw new Exception('Username is already taken', 400);
            }

            $updateStmt = $this->pdo->prepare("UPDATE users SET username = :username WHERE id = :user_id");
            $updateStmt->execute(['username' => $newUsername, 'user_id' => $this->userId]);

            $this->pdo->commit();

            $_SESSION['username'] = $newUsername;
            logDebug("Username updated - User ID: {$this->userId}, New Username: {$newUsername}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Username updated successfully',
                'new_username' => $newUsername
            ]);
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during username update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update username', 500);
        }
    }

    private function updateEmail(string $newEmail): void
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare("SELECT id FROM users WHERE email = :email AND id != :user_id");
            $stmt->execute(['email' => $newEmail, 'user_id' => $this->userId]);

            if ($stmt->fetch()) {
                logWarning("Email already registered - User ID: {$this->userId}, Email: {$newEmail}");
                throw new RuntimeException('Email is already registered', 400);
            }

            $updateStmt = $this->pdo->prepare("
                UPDATE users 
                SET email = :email
                WHERE id = :user_id
            ");
            $updateStmt->execute([
                'email' => $newEmail,
                'user_id' => $this->userId
            ]);

            $this->pdo->commit();

            if ($updateStmt->rowCount() === 0) {
                logError("Email update failed - User ID: {$this->userId}");
                throw new RuntimeException('Failed to update email', 500);
            }

            logDebug("Email updated successfully - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Email updated successfully. Please verify your new email.',
                'new_email' => htmlspecialchars($newEmail, ENT_QUOTES, 'UTF-8')
            ]);

        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during email update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update email', 500);
        }
    }

    private function updateFullName(string $newFullName): void
    {
        $this->pdo->beginTransaction();
        try {
            $sanitizedFullName = htmlspecialchars($newFullName, ENT_QUOTES, 'UTF-8');
            $stmt = $this->pdo->prepare("SELECT user_id FROM user_profiles WHERE user_id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            if ($stmt->fetch()) {
                $updatedStmt = $this->pdo->prepare("UPDATE user_profiles SET full_name = :full_name WHERE user_id = :user_id");
            } else {
                $updatedStmt = $this->pdo->prepare("INSERT INTO  user_profiles (user_id, full_name) VALUES (:user_id, :full_name)");
            }

            $updatedStmt->execute([
                'user_id' => $this->userId,
                'full_name' => $sanitizedFullName
            ]);

            $this->pdo->commit();
            logDebug("Full name updated - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Name updated successfully',
                'new_bio' => $sanitizedFullName
            ]);
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during name update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update name', 500);
        }
    }

    private function updateBio(string $newBio): void
    {
        $this->pdo->beginTransaction();
        try {
            $sanitizedBio = htmlspecialchars(trim($newBio), ENT_QUOTES, 'UTF-8');

            $stmt = $this->pdo->prepare("SELECT user_id FROM user_profiles WHERE user_id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);

            if ($stmt->fetch()) {
                $updateStmt = $this->pdo->prepare("UPDATE user_profiles SET bio = :bio WHERE user_id = :user_id");
            } else {
                $updateStmt = $this->pdo->prepare("INSERT INTO user_profiles (user_id, bio) VALUES (:user_id, :bio)");
            }

            $updateStmt->execute([
                'bio' => $sanitizedBio,
                'user_id' => $this->userId
            ]);

            $this->pdo->commit();

            logDebug("Bio updated successfully - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Bio updated successfully',
                'new_bio' => $sanitizedBio
            ]);

        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during bio update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update bio', 500);
        }
    }

    private function updateSocialLinks(array $socialData): void
    {
        try {
            $allowedPlatforms = ['github', 'twitter', 'website'];
            $sanitizedData = [];

            foreach ($allowedPlatforms as $platform) {
                $url = $socialData[$platform] ?? '';

                if (!empty($url)) {
                    if (!filter_var($url, FILTER_VALIDATE_URL)) {
                        logWarning("Invalid {$platform} URL - User ID: {$this->userId}, URL: {$url}");
                        throw new InvalidArgumentException("Invalid {$platform} URL", 400);
                    }

                    if (strlen($url) > $this->generalConfig['user']['MAX_SOCIAL_URL_LENGTH']) {
                        logWarning("{$platform} URL too long - User ID: {$this->userId}");
                        throw new InvalidArgumentException("{$platform} URL is too long", 400);
                    }

                    $sanitizedData[$platform] = filter_var($url, FILTER_SANITIZE_URL);
                } else {
                    $sanitizedData[$platform] = null;
                }
            }

            $this->pdo->beginTransaction();

            $stmt = $this->pdo->prepare("SELECT user_id FROM user_profiles WHERE user_id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);

            if ($stmt->fetch()) {
                $updateStmt = $this->pdo->prepare("
                    UPDATE user_profiles
                    SET github_url = :github, 
                        twitter_url = :twitter, 
                        website_url = :website
                    WHERE user_id = :user_id
                ");
            } else {
                $updateStmt = $this->pdo->prepare("
                    INSERT INTO user_profiles
                    (user_id, github_url, twitter_url, website_url)
                    VALUES (:user_id, :github, :twitter, :website)
                ");
            }

            $updateStmt->execute([
                'github' => $sanitizedData['github'],
                'twitter' => $sanitizedData['twitter'],
                'website' => $sanitizedData['website'],
                'user_id' => $this->userId
            ]);

            $this->pdo->commit();

            logDebug("Social links updated - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Social links updated successfully',
                'social_links' => $sanitizedData
            ]);

        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during social links update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update social links', 500);
        }
    }

    private function handleAvatarUpload(): void
    {
        try {
            if (!isset($_FILES['avatar']) || !is_uploaded_file($_FILES['avatar']['tmp_name'])) {
                logWarning("Invalid file upload attempt - User ID: {$this->userId}");
                throw new InvalidArgumentException('No file uploaded or upload error', 400);
            }

            $file = $_FILES['avatar'];

            if ($file['error'] !== UPLOAD_ERR_OK) {
                logWarning("File upload error - User ID: {$this->userId}, Error Code: {$file['error']}");
                throw new RuntimeException('File upload failed', 400);
            }

            if ($file['size'] > $this->generalConfig['user']['MAX_AVATAR_SIZE']) {
                logWarning("Avatar file too large - User ID: {$this->userId}, Size: {$file['size']}");
                throw new InvalidArgumentException(sprintf('Image must be less than %dMB', $this->generalConfig['user']['MAX_AVATAR_SIZE'] / 1024 / 1024), 400);
            }

            $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
            $mimeType = finfo_file($fileInfo, $file['tmp_name']);
            finfo_close($fileInfo);

            if (!in_array($mimeType, $this->generalConfig['user']['ALLOWED_AVATAR_TYPES'])) {
                logWarning("Invalid avatar file type - User ID: {$this->userId}, Type: {$mimeType}");
                throw new InvalidArgumentException(
                    sprintf('Only %s images are allowed', implode(', ', $this->generalConfig['user']['ALLOWED_AVATAR_TYPES'])),
                    400
                );
            }

            $stmt = $this->pdo->prepare("SELECT avatar_url FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $oldAvatar = $stmt->fetch();
            $oldAvatarUrl = $oldAvatar['avatar_url'] ?? '';

            if ($oldAvatarUrl && strpos($oldAvatarUrl, '/uploads/avatars/') === 0) {
                $oldFilePath = $_SERVER['DOCUMENT_ROOT'] . $oldAvatarUrl;
                if (file_exists($oldFilePath) && is_writable($oldFilePath)) {
                    if (!unlink($oldFilePath)) {
                        logError("Failed to delete old avatar - User ID: {$this->userId}, Path: {$oldFilePath}");
                        throw new RuntimeException('Error processing avatar', 500);
                    }
                }
            }

            $extensionMap = [
                'image/jpeg' => 'jpg',
                'image/png' => 'png',
                'image/gif' => 'gif'
            ];
            $extension = $extensionMap[$mimeType] ?? 'jpg';
            $filename = 'avatar_' . $this->userId . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
            $uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/avatars/';
            $uploadPath = '/uploads/avatars/' . $filename;
            $fullPath = $uploadDir . $filename;

            if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true)) {
                logError("Failed to create avatar directory - Path: {$uploadDir}");
                throw new RuntimeException('Failed to process avatar', 500);
            }

            if (!move_uploaded_file($file['tmp_name'], $fullPath)) {
                logError("Failed to save avatar - User ID: {$this->userId}, Path: {$fullPath}");
                throw new RuntimeException('Error processing request', 500);
            }

            chmod($fullPath, 0644);

            $updateStmt = $this->pdo->prepare("UPDATE users SET avatar_url = :avatar_url WHERE id = :user_id");
            $updateStmt->execute([
                'avatar_url' => $uploadPath,
                'user_id' => $this->userId
            ]);

            logDebug("Avatar updated successfully - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Avatar updated successfully',
                'avatar_url' => $uploadPath
            ]);

        } catch (PDOException $e) {
            logError("Database error during avatar update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update avatar', 500);
        }
    }

    private function handleAvatarUpdate(): void
    {
        try {
            $input = file_get_contents('php://input');
            if ($input === false) {
                throw new RuntimeException('Failed to read input data', 400);
            }

            $data = json_decode($input, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidArgumentException('Invalid JSON data', 400);
            }

            $avatar = $data['avatar'] ?? null;
            if ($avatar === null) {
                throw new InvalidArgumentException('Avatar selection cannot be empty', 400);
            }

            $allowedAvatars = ['avatar1', 'avatar2', 'avatar3'];
            if (!in_array($avatar, $allowedAvatars, true)) {
                throw new InvalidArgumentException('Invalid avatar selection', 400);
            }

            $stmt = $this->pdo->prepare("SELECT avatar_url FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $oldAvatar = $stmt->fetch();
            $oldAvatarUrl = $oldAvatar['avatar_url'] ?? '';

            if ($oldAvatarUrl && strpos($oldAvatarUrl, '/uploads/avatars/') === 0) {
                $oldFilePath = $_SERVER['DOCUMENT_ROOT'] . $oldAvatarUrl;
                if (file_exists($oldFilePath) && is_writable($oldFilePath)) {
                    if (!unlink($oldFilePath)) {
                        logError("Failed to delete old avatar file - User ID: {$this->userId}, Path: {$oldFilePath}");
                        throw new RuntimeException('Could not delete old avatar file', 500);
                    }
                }
            }

            $avatarPath = '/assets/avatars/' . basename($avatar) . '.png';

            $updateStmt = $this->pdo->prepare("UPDATE users SET avatar_url = :avatar_url WHERE id = :user_id");
            $updateStmt->execute([
                'avatar_url' => $avatarPath,
                'user_id' => $this->userId
            ]);

            logDebug("Avatar updated via selection - User ID: {$this->userId}, Avatar: {$avatar}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Avatar updated successfully',
                'avatar_url' => $avatarPath
            ]);

        } catch (PDOException $e) {
            logError("Database error during avatar update - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to update avatar', 500);
        }
    }

    private function changePassword(string $currentPassword, string $newPassword): void
    {
        $this->pdo->beginTransaction();
        try {
            if (empty($currentPassword) || empty($newPassword)) {
                throw new InvalidArgumentException('Both current and new password are required', 400);
            }

            if (strlen($newPassword) < $this->generalConfig['user']['MIN_PASSWORD_LENGTH']) {
                throw new InvalidArgumentException('New password must be at least 8 characters', 400);
            }

            if (strlen($newPassword) > $this->generalConfig['user']['MAX_PASSWORD_LENGTH']) {
                throw new InvalidArgumentException('Password is too long', 400);
            }

            $stmt = $this->pdo->prepare("SELECT password_hash FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                logError("User not found during password change - User ID: {$this->userId}");
                throw new RuntimeException('User not found', 404);
            }

            if (!password_verify($currentPassword, $user['password_hash'])) {
                logWarning("Incorrect current password attempt - User ID: {$this->userId}");
                throw new InvalidArgumentException('Current password is incorrect', 400);
            }

            if (password_verify($newPassword, $user['password_hash'])) {
                throw new InvalidArgumentException('New password must be different from current password', 400);
            }

            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
            if ($newHash === false) {
                throw new RuntimeException('Error hashing password', 500);
            }

            $updateStmt = $this->pdo->prepare("UPDATE users SET password_hash = :password WHERE id = :user_id");
            $updateStmt->execute([
                'password' => $newHash,
                'user_id' => $this->userId
            ]);

            $this->pdo->commit();

            logDebug("Password changed successfully - User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Password changed successfully'
            ]);

        } catch (PDOException $e) {
            $this->pdo->rollBack();
            logError("Database error during password change - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to change password', 500);
        }
    }

    private function getCategoryData(): array
    {
        try {
            $stmt = $this->pdo->query("SELECT unnest(enum_range(NULL::challenge_category)) AS category ORDER BY category");
            $allCategories = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($allCategories)) {
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
                'percentages' => array_values($percentages),
                'solved_counts' => array_replace(array_fill_keys($allCategories, 0), $solved)
            ];

        } catch (PDOException $e) {
            logError("Database error in getCategoryData - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to retrieve category data', 500);
        }
    }

    private function handleVpnConfigDownload(): void
    {
        try {
            $configDir = '/var/lib/ctf-challenger/vpn-configs/';
            $configFile = $configDir . 'user_' . $this->userId . '.ovpn';

            if (!file_exists($configFile) || !is_readable($configFile)) {
                logError("VPN config not found or inaccessible - User ID: {$this->userId}, Path: {$configFile}");
                throw new RuntimeException('VPN configuration not found. Please contact support.', 404);
            }

            $stmt = $this->pdo->prepare("SELECT username FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);
            $username = $userData['username'] ?? 'user_' . $this->userId;

            $safeUsername = preg_replace('/' . $this->generalConfig['user']['USERNAME_REGEX'] . '/', '', $username);
            $filename = 'vpn_config_' . $safeUsername . '.ovpn';

            while (ob_get_level()) {
                ob_end_clean();
            }

            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
            header('Pragma: public');
            header('Content-Length: ' . filesize($configFile));
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');

            readfile($configFile);
            exit;

        } catch (PDOException $e) {
            logError("Database error during VPN config download - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to process VPN configuration', 500);
        }
    }

    private function handleDeleteRequest(): void
    {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                logWarning("Invalid JSON in delete request - User ID: {$this->userId}");
                throw new Exception('Invalid request data', 400);
            }

            $password = $input['password'] ?? '';
            $this->verifyUserPassword($password);
            $this->stopRunningChallenge();
            $this->deleteUserConfigurations();
            $this->deleteUserOvaFiles();
            $this->deleteAllUserData();
            $this->destroyUserSession();

            logInfo("Account deleted successfully - User ID: {$this->userId}");
            $this->sendSuccessResponse();

        } catch (Exception $e) {
            logError("Account deletion failed - User ID: {$this->userId} - " . $e->getMessage());
            throw $e;
        }
    }

    private function verifyUserPassword(string $password): void
    {
        try {
            if (empty($password)) {
                throw new InvalidArgumentException('Password cannot be empty', 400);
            }

            $stmt = $this->pdo->prepare("SELECT password_hash FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || !password_verify($password, $user['password_hash'])) {
                logWarning("Incorrect password during verification - User ID: {$this->userId}");
                throw new InvalidArgumentException('Incorrect password', 400);
            }

        } catch (PDOException $e) {
            logError("Database error during password verification - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to verify password', 500);
        }
    }

    private function stopRunningChallenge(): void
    {
        try {
            $stmt = $this->pdo->prepare("SELECT running_challenge FROM users WHERE id = :user_id");
            $stmt->execute(['user_id' => $this->userId]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($result && $result['running_challenge'] !== null) {
                $response = makeBackendRequest(
                    '/stop-challenge',
                    'POST',
                    getBackendHeaders(),
                    ['user_id' => $this->userId]
                );

                if (!$response['success'] || $response['http_code'] !== 200) {
                    logError("Failed to stop running challenge - User ID: {$this->userId}, Response: " . json_encode($response));
                    throw new RuntimeException("Failed to stop current challenge", 500);
                }
                logDebug("Stopped running challenge - User ID: {$this->userId}");
            }

        } catch (PDOException $e) {
            logError("Database error during challenge stop - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to stop running challenge', 500);
        }
    }

    private function deleteUserConfigurations(): void
    {
        try {
            $response = makeBackendRequest(
                '/delete-user-config',
                'POST',
                getBackendHeaders(),
                ['user_id' => $this->userId]
            );

            if (!$response['success'] || $response['http_code'] !== 200) {
                logError("Failed to delete user config - User ID: {$this->userId}, Response: " . json_encode($response));
                throw new RuntimeException("Failed to process request", 500);
            }
        } catch (Exception $e) {
            logError("Error deleting user configurations - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to process request', 500);
        }
    }

    private function deleteUserOvaFiles(): void
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT id AS ova_id, proxmox_filename 
                FROM disk_files 
                WHERE user_id = :user_id
            ");
            $stmt->execute(['user_id' => $this->userId]);
            $ovas = $stmt->fetchAll(PDO::FETCH_ASSOC);

            foreach ($ovas as $ova) {
                try {
                    $endpoint = "/api2/json/nodes/" . $this->config['upload']['NODE'] . "/storage/local/content/import/" .
                        urlencode($ova['proxmox_filename']);
                    $result = makeCurlRequest($endpoint, 'DELETE', getAuthHeaders());

                    if (!$result || $result['http_code'] !== 200) {
                        throw new RuntimeException('Failed to delete virtual machine', 500);
                    }

                    $this->pdo->prepare("DELETE FROM disk_files WHERE id = ? AND user_id = ?")
                        ->execute([$ova['ova_id'], $this->userId]);
                } catch (Exception $e) {
                    logError("Failed to delete OVA - User ID: {$this->userId}, OVA ID: {$ova['ova_id']} - " . $e->getMessage());
                }
            }

        } catch (PDOException $e) {
            logError("Database error during OVA deletion - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to delete OVA files', 500);
        }
    }

    private function deleteAllUserData(): void
    {
        try {
            $this->pdo->beginTransaction();

            $tables = [
                'user_badges',
                'completed_challenges',
                'user_profiles',
                'user_sessions',
                'password_resets',
                'email_verifications',
                'disk_files'
            ];

            foreach ($tables as $table) {
                $this->pdo->prepare("DELETE FROM $table WHERE user_id = ?")
                    ->execute([$this->userId]);
            }

            $this->pdo->prepare("UPDATE vpn_static_ips SET user_id = NULL WHERE user_id = ?")
                ->execute([$this->userId]);

            $this->pdo->prepare("DELETE FROM users WHERE id = ?")
                ->execute([$this->userId]);

            $this->pdo->commit();
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("Failed to delete all user data - User ID: {$this->userId} - " . $e->getMessage());
            throw new RuntimeException('Failed to delete account data', 500);
        }
    }

    private function destroyUserSession(): void
    {
        try {
            session_regenerate_id(true);
            $_SESSION = [];

            if (session_status() === PHP_SESSION_ACTIVE) {
                session_destroy();
            }

            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires' => time() - 3600,
                    'path' => $params['path'],
                    'domain' => $params['domain'],
                    'secure' => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite']
                ]
            );

            setcookie(
                'csrf_token',
                '',
                [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'domain' => '',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]
            );

        } catch (Exception $e) {
            logError("Error destroying session - " . $e->getMessage());
            throw new RuntimeException('Failed to destroy session', 500);
        }
    }

    private function sendSuccessResponse(): void
    {
        $this->sendResponse([
            'success' => true,
            'message' => 'Account deleted successfully',
            'redirect' => '/'
        ]);
    }

    private function sendResponse(array $response): void
    {
        echo json_encode($response);
    }

    private function handleError(Exception $e): void
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $e->getMessage();

        if ($errorCode === 401) {
            session_unset();
            session_destroy();
            logWarning("Session destroyed due to unauthorized access");
        }

        if ($errorCode >= 500) {
            $errorMessage = 'An internal server error occurred';
            logError("Internal error : " . $e->getMessage());
        } else {
            logError("Profile error: " . $e->getMessage());
        }

        http_response_code($errorCode);
        $this->sendResponse([
            'success' => false,
            'message' => $errorMessage,
            'redirect' => $errorCode === 401 ? '/login' : null
        ]);
    }
}

try {
    $handler = new ProfileHandler($config, $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    logError("Error in profile endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}