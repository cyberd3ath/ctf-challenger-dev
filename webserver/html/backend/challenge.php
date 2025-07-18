<?php
declare(strict_types=1);

header('Content-Type: application/json');

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/curlHelper.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/challengeHelper.php';
$config = require __DIR__ . '/../config/backend.config.php';

class ChallengeHandler
{
    private PDO $pdo;
    private ?int $userId;
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->initSession();
        $this->validateCSRF();
        $this->pdo = getPDO();
        $this->userId = $_SESSION['user_id'];
        logDebug("Initialized ChallengeHandler for user ID: {$this->userId}");
    }

    private function initSession()
    {
        init_secure_session();

        if (!validate_session()) {
            logWarning("Unauthorized access attempt to challenge route - IP: " . anonymizeIp($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            throw new Exception('Unauthorized - Please login', 401);
        }
    }

    private function validateCSRF()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!validate_csrf_token($csrfToken)) {
            logWarning("Invalid CSRF token in challenge route - User ID: " . ($_SESSION['user_id'] ?? 'unknown'));
            throw new Exception('Invalid CSRF token', 403);
        }
    }

    public function handleRequest()
    {
        try {
            $method = $_SERVER['REQUEST_METHOD'];

            switch ($method) {
                case 'POST':
                    $this->handlePostRequest();
                    break;
                case 'GET':
                    $this->handleGetRequest();
                    break;
                default:
                    logWarning("Invalid request method in challenge route - Method: {$method}");
                    throw new Exception('Method not allowed', 405);
            }
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function handlePostRequest()
    {
        $input = $this->getJsonInput();
        $this->validatePostInput($input);

        $challengeId = $this->validateChallengeId($input['challenge_id']);
        $action = $input['action'];

        switch ($action) {
            case 'deploy':
                $this->handleDeploy($challengeId);
                break;
            case 'cancel':
                $this->handleCancel($challengeId);
                break;
            case 'submit_flag':
                $this->handleFlagSubmission($challengeId, $input);
                break;
            case 'extend_time':
                $this->handleTimeExtension($challengeId);
                break;
        }
    }

    private function getJsonInput()
    {
        $input = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            logWarning("Invalid JSON input in challenge route - User ID: {$this->userId}");
            throw new Exception('Invalid JSON input', 400);
        }
        return $input;
    }

    private function validatePostInput(array $input)
    {
        $requiredFields = ['action', 'challenge_id'];
        foreach ($requiredFields as $field) {
            if (!isset($input[$field])) {
                logWarning("Missing required field in challenge route - Field: {$field}, User ID: {$this->userId}");
                throw new Exception("Missing required parameter: {$field}", 400);
            }
        }

        if (!in_array($input['action'], $this->config['challenge']['ALLOWED_ACTIONS'])) {
            logWarning("Invalid action in challenge route - Action: {$input['action']}, User ID: {$this->userId}");
            throw new Exception('Invalid action', 400);
        }
    }

    private function validateChallengeId($challengeId)
    {
        $id = filter_var($challengeId, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($id === false) {
            logWarning("Invalid challenge ID - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception('Invalid challenge ID', 400);
        }
        return $id;
    }

    private function handleDeploy(int $challengeId)
    {
        $this->checkRunningChallenge();
        $this->validateChallengeStatus($challengeId);

        $result = makeBackendRequest(
            '/launch-challenge',
            'POST',
            getBackendHeaders(),
            [
                'user_id' => $this->userId,
                'challenge_template_id' => $challengeId
            ]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            $errorMsg = $result['error'] ?? "HTTP {$result['http_code']}";
            logError("Failed to launch challenge - Error: {$errorMsg}, User ID: {$this->userId}");
            throw new Exception("Failed to launch challenge: {$errorMsg}", 500);
        }

        $responseData = json_decode($result['response'], true);
        $entrypoints = $responseData['entrypoints'] ?? [];

        $this->startNewAttempt($challengeId);

        logDebug("Challenge deployed successfully - ID: {$challengeId}, User ID: {$this->userId}");

        $this->sendResponse([
            'success' => true,
            'message' => 'Challenge deployment initiated',
            'entrypoints' => $entrypoints,
            'elapsed_seconds' => getElapsedSecondsForChallenge($this->pdo,$this->userId,$challengeId),
            'remaining_seconds' => $this->getRemainingSecondsForChallenge($challengeId),
            'remaining_extensions' => $this->getRemainingExtensionsForChallenge($challengeId)
        ]);
    }

    private function checkRunningChallenge()
    {
        $stmt = $this->pdo->prepare("SELECT running_challenge FROM users WHERE id = :user_id");
        $stmt->execute(['user_id' => $this->userId]);
        $user = $stmt->fetch();

        if ($user['running_challenge']) {
            logWarning("User already has a running challenge - User ID: {$this->userId}");
            throw new Exception("You already have a running challenge", 400);
        }
    }

    private function validateChallengeStatus(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT marked_for_deletion, is_active 
            FROM challenge_templates 
            WHERE id = :template_id
        ");
        $stmt->execute(['template_id' => $challengeId]);
        $template = $stmt->fetch();

        if (!$template) {
            logWarning("Challenge not found - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("Challenge not found", 404);
        }

        if ($template['marked_for_deletion']) {
            logWarning("Attempt to deploy challenge marked for deletion - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("This challenge has been marked for deletion and cannot be deployed", 400);
        }

        if (!$template['is_active'] && !$this->isCreator($challengeId)) {
            logWarning("Attempt to deploy inactive challenge - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("This challenge is currently inactive and cannot be deployed", 400);
        }
    }

    private function isCreator(int $challengeId)
    {
        try{
            $stmt = $this->pdo->prepare("
                SELECT creator_id
                FROM challenge_templates
                WHERE id = :challenge_id
            ");
            $stmt->execute(['challenge_id' => $challengeId]);
            $creatorId = $stmt->fetchColumn();
            if($creatorId === $this->userId){
                return true;
            }
            return false;
        }catch (PDOException $e){
            logError("Failed to check Creator - Challenge ID: {$challengeId}, Error: {$e->getMessage()}");
            throw new Exception("Failed to start Challenge", 500);
        }
    }

    private function startNewAttempt(int $challengeId)
    {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO completed_challenges (
                    user_id, 
                    challenge_template_id, 
                    started_at
                ) VALUES (
                    :user_id, 
                    :challenge_template_id, 
                    NOW()
                )
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'challenge_template_id' => $challengeId
            ]);
            logDebug("New attempt started - Challenge ID: {$challengeId}, User ID: {$this->userId}");
        } catch (PDOException $e) {
            logError("Failed to start new attempt - Challenge ID: {$challengeId}, Error: " . $e->getMessage());
            throw new Exception("Failed to start challenge attempt", 500);
        }
    }

    private function handleCancel(int $challengeId)
    {
        $this->stopRunningChallenge();
        $this->markAttemptAsCompleted($challengeId);

        if ($this->shouldDeleteChallengeTemplate($challengeId)) {
            $this->deleteChallengeTemplate($challengeId);
        }

        $this->sendResponse([
            'success' => true,
            'message' => 'Challenge cancelled successfully'
        ]);
    }

    private function stopRunningChallenge()
    {
        $result = makeBackendRequest(
            '/stop-challenge',
            'POST',
            getBackendHeaders(),
            ['user_id' => $this->userId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            $errorMsg = $result['error'] ?? "HTTP {$result['http_code']}";
            logError("Failed to stop challenge - Error: {$errorMsg}, User ID: {$this->userId}");
            throw new Exception("Failed to stop challenge: {$errorMsg}", 500);
        }
    }

    private function markAttemptAsCompleted(int $challengeId)
    {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE completed_challenges
                SET completed_at = NOW()
                WHERE user_id = :user_id
                AND challenge_template_id = :challenge_id
                AND completed_at IS NULL
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'challenge_id' => $challengeId
            ]);
            logDebug("Marked attempt as completed - Challenge ID: {$challengeId}, User ID: {$this->userId}");
        } catch (PDOException $e) {
            logError("Failed to mark attempt as completed - Challenge ID: {$challengeId}, Error: " . $e->getMessage());
            throw new Exception("Failed to complete challenge attempt", 500);
        }
    }

    private function shouldDeleteChallengeTemplate(int $challengeId)
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) 
                FROM challenges 
                WHERE challenge_template_id = :template_id
            ");
            $stmt->execute(['template_id' => $challengeId]);
            $remainingInstances = $stmt->fetchColumn();

            $stmt = $this->pdo->prepare("
                SELECT marked_for_deletion 
                FROM challenge_templates 
                WHERE id = :template_id
            ");
            $stmt->execute(['template_id' => $challengeId]);
            $markedForDeletion = $stmt->fetchColumn();

            return $markedForDeletion && $remainingInstances === 0;
        } catch (PDOException $e) {
            logError("Failed to check template deletion status - Challenge ID: {$challengeId}, Error: " . $e->getMessage());
            return false;
        }
    }

    private function deleteChallengeTemplate(int $challengeId)
    {
        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare("
                DELETE FROM completed_challenges
                WHERE challenge_template_id = :challenge_id
            ");
            $stmt->execute(['challenge_id' => $challengeId]);

            $result = makeBackendRequest(
                '/delete-machine-templates',
                'POST',
                getBackendHeaders(),
                ['challenge_id' => $challengeId]
            );

            if (!$result['success'] || $result['http_code'] !== 200) {
                throw new Exception("Failed to delete VM templates: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
            }

            $tables = [
                'challenge_flags',
                'challenge_hints',
                'network_connection_templates',
                'machine_templates',
                'network_templates',
                'challenge_templates'
            ];

            foreach ($tables as $table) {
                switch ($table) {
                    case 'network_connection_templates':
                        $stmt = $this->pdo->prepare("
                            DELETE FROM network_connection_templates
                            WHERE machine_template_id IN (
                                SELECT id FROM machine_templates 
                                WHERE challenge_template_id = :challenge_id
                            )
                        ");
                        break;
                    case 'machine_templates':
                        $stmt = $this->pdo->prepare("
                            DELETE FROM machine_templates 
                            WHERE challenge_template_id = :challenge_id
                        ");
                        break;
                    case 'network_templates':
                        $stmt = $this->pdo->prepare("
                            DELETE FROM network_templates
                            WHERE id IN (
                                SELECT nct.network_template_id
                                FROM network_connection_templates nct
                                JOIN machine_templates mt ON nct.machine_template_id = mt.id
                                WHERE mt.challenge_template_id = :challenge_id
                            )
                            AND NOT EXISTS (
                                SELECT 1 FROM network_connection_templates nct2
                                WHERE nct2.network_template_id = network_templates.id
                                AND nct2.machine_template_id NOT IN (
                                    SELECT id FROM machine_templates 
                                    WHERE challenge_template_id = :challenge_id
                                )
                            )
                        ");
                        break;
                    case 'challenge_templates':
                        $stmt = $this->pdo->prepare("
                            DELETE FROM challenge_templates 
                            WHERE id = :challenge_id
                        ");
                        break;
                    default:
                        $stmt = $this->pdo->prepare("
                            DELETE FROM {$table} 
                            WHERE challenge_template_id = :challenge_id
                        ");
                        break;
                }

                $stmt->execute(['challenge_id' => $challengeId]);
            }

            $this->pdo->commit();
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("Failed to delete challenge template - ID: {$challengeId}, Error: " . $e->getMessage());
            throw new Exception("Failed to delete challenge template", 500);
        }
    }

    private function handleFlagSubmission(int $challengeId, array $input)
    {
        if (!isset($input['flag'])) {
            logWarning("Flag submission attempt without flag - User ID: {$this->userId}");
            throw new Exception("Flag missing", 400);
        }

        $flag = trim($input['flag']);
        if (empty($flag)) {
            logWarning("Empty flag submission attempt - User ID: {$this->userId}");
            throw new Exception("Flag cannot be empty", 400);
        }

        $this->pdo->beginTransaction();

        try {
            $flagData = $this->validateAndLockFlag($challengeId, $flag);
            $this->checkDuplicateSubmission($challengeId, $flagData['id']);

            $submittedFlagsCount = $this->countSubmittedFlags($challengeId);
            $totalFlagsCount = $this->countTotalFlags($challengeId);
            $isLastFlag = ($submittedFlagsCount + 1) >= $totalFlagsCount;

            $this->recordFlagSubmission($challengeId, $flagData['id'], $isLastFlag);
            $this->pdo->commit();

            $newBadges = [];
            if ($isLastFlag) {
                $newBadges = $this->checkBadgeUnlocks($challengeId);
                logDebug("User completed all flags - Challenge ID: {$challengeId}, User ID: {$this->userId}");
            }

            logDebug("Flag accepted - Challenge ID: {$challengeId}, Points: {$flagData['points']}, User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Flag accepted! You earned ' . $flagData['points'] . ' points!',
                'badges' => $newBadges,
                'is_complete' => $isLastFlag
            ]);
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("Flag submission failed - Challenge ID: {$challengeId}, Error: " . $e->getMessage());
            throw $e;
        }
    }

    private function validateAndLockFlag(int $challengeId, string $flag)
    {
        $stmt = $this->pdo->prepare("
            SELECT id, points FROM challenge_flags 
            WHERE challenge_template_id = :challenge_id 
            AND flag = :flag
            FOR UPDATE
        ");
        $stmt->execute([
            'challenge_id' => $challengeId,
            'flag' => $flag
        ]);
        $flagData = $stmt->fetch();

        if (!$flagData) {
            logWarning("Invalid flag submitted - Challenge ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("Invalid flag", 400);
        }

        return $flagData;
    }

    private function checkDuplicateSubmission(int $challengeId, int $flagId)
    {
        $stmt = $this->pdo->prepare("
            SELECT 1 FROM completed_challenges
            WHERE user_id = :user_id 
            AND challenge_template_id = :challenge_id
            AND flag_id = :flag_id
            FOR UPDATE
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId,
            'flag_id' => $flagId
        ]);

        if ($stmt->fetch()) {
            logWarning("Duplicate flag submission - Flag ID: {$flagId}, User ID: {$this->userId}");
            throw new Exception("You already submitted this flag", 400);
        }
    }

    private function countSubmittedFlags(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT flag_id) 
            FROM completed_challenges
            WHERE user_id = :user_id
            AND challenge_template_id = :challenge_id
            AND flag_id IS NOT NULL
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);
        return (int)$stmt->fetchColumn();
    }

    private function countTotalFlags(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(id) FROM challenge_flags
            WHERE challenge_template_id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
        return $stmt->fetchColumn();
    }

    private function recordFlagSubmission(int $challengeId, int $flagId, bool $isLastFlag)
    {
        $activeAttempt = $this->getActiveAttempt($challengeId);

        if ($activeAttempt) {
            if ($isLastFlag) {
                $this->updateRunningAttempt($activeAttempt['id'], $flagId);
            } else {
                $this->createNewCompletedAttempt($challengeId, $flagId);
            }
        } else {
            $this->handleNoActiveAttempt($challengeId, $flagId);
        }
    }

    private function getActiveAttempt(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT id FROM completed_challenges
            WHERE user_id = :user_id
            AND challenge_template_id = :challenge_id
            AND completed_at IS NULL
            FOR UPDATE
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);
        return $stmt->fetch();
    }

    private function updateRunningAttempt(int $attemptId, int $flagId)
    {
        $stmt = $this->pdo->prepare("
            UPDATE completed_challenges
            SET flag_id = :flag_id,
                completed_at = NOW()
            WHERE id = :attempt_id
        ");
        $stmt->execute([
            'flag_id' => $flagId,
            'attempt_id' => $attemptId
        ]);
    }

    private function createNewCompletedAttempt(int $challengeId, int $flagId)
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO completed_challenges (
                user_id, 
                challenge_template_id, 
                flag_id,
                started_at,
                completed_at
            ) VALUES (
                :user_id, 
                :challenge_template_id, 
                :flag_id,
                NOW(),
                NOW()
            )
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_template_id' => $challengeId,
            'flag_id' => $flagId
        ]);
    }

    private function handleNoActiveAttempt(int $challengeId, int $flagId)
    {
        $recentAttempt = $this->getRecentUnflaggedAttempt($challengeId);

        if ($recentAttempt) {
            $this->updateRecentAttempt($recentAttempt['id'], $flagId);
        } else {
            $this->createNewCompletedAttempt($challengeId, $flagId);
        }
    }

    private function getRecentUnflaggedAttempt(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT id FROM completed_challenges
            WHERE user_id = :user_id
            AND challenge_template_id = :challenge_id
            AND flag_id IS NULL
            AND completed_at IS NOT NULL
            ORDER BY started_at DESC
            LIMIT 1
            FOR UPDATE
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);
        return $stmt->fetch();
    }

    private function updateRecentAttempt(int $attemptId, int $flagId)
    {
        $stmt = $this->pdo->prepare("
            UPDATE completed_challenges
            SET flag_id = :flag_id
            WHERE id = :attempt_id
        ");
        $stmt->execute([
            'flag_id' => $flagId,
            'attempt_id' => $attemptId
        ]);
    }

    private function handleGetRequest()
    {
        $challengeId = $this->validateChallengeId($_GET['id'] ?? 0);

        try {
            $challenge = $this->getChallengeDetails($challengeId);
            $challengeStatus = $this->getChallengeStatus($challengeId);
            $isSolved = isChallengeSolved($this->pdo, $this->userId, $challengeId);
            $solution = $this->getChallengeSolution($challengeId, $isSolved);
            $flags = $this->getChallengeFlags($challengeId);
            $completedFlagIds = $this->getCompletedFlagIds($challengeId);
            $userPoints = $this->calculateUserPoints($flags, $completedFlagIds);
            $challengePoints = $this->calculateChallengePoints($flags);
            $hints = $this->getChallengeHints($challengeId, $userPoints);
            $entrypoints = $this->getEntrypointsIfRunning($challengeStatus);
            $elapsedSeconds = getElapsedSecondsForChallenge($this->pdo,$this->userId,$challengeId);
            $remainingSeconds = $this->getRemainingSecondsForChallenge($challengeId);
            $remainingExtensions = $this->getRemainingExtensionsForChallenge($challengeId);
            $leaderboard = getSolvedLeaderboard($this->pdo,$challengeId);

            $this->sendResponse([
                'success' => true,
                'challenge' => array_merge($challenge, [
                    'challenge_status' => $challengeStatus,
                    'hints' => $hints,
                    'solution' => $solution,
                    'user_points' => $userPoints,
                    'challenge_points' => $challengePoints,
                    'entrypoints' => $entrypoints,
                    'elapsed_seconds' => $elapsedSeconds,
                    'remaining_seconds' => $remainingSeconds,
                    'remaining_extensions' => $remainingExtensions,
                    'isSolved' => $isSolved,
                    'leaderboard' => $leaderboard,
                ])
            ]);
        } catch (Exception $e) {
            logError("Failed to fetch challenge details - ID: {$challengeId}, Error: " . $e->getMessage());
            throw $e;
        }
    }

    private function getChallengeDetails(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT 
                ct.id,
                ct.name,
                ct.description,
                ct.category,
                ct.difficulty,
                ct.image_path,
                ct.is_active,
                ct.created_at,
                ct.updated_at,
                ct.hint,
                ct.marked_for_deletion,
                u.username as creator_username,
                ct.creator_id,
                (
                    SELECT COUNT(DISTINCT cc.user_id)
                    FROM completed_challenges cc
                    WHERE cc.challenge_template_id = ct.id
                    AND (
                        SELECT COUNT(DISTINCT cf.id)
                        FROM challenge_flags cf
                        WHERE cf.challenge_template_id = ct.id
                    ) = (
                        SELECT COUNT(DISTINCT cc2.flag_id)
                        FROM completed_challenges cc2
                        JOIN challenge_flags cf ON cc2.flag_id = cf.id
                        WHERE cc2.user_id = cc.user_id
                        AND cc2.challenge_template_id = ct.id
                        AND cf.challenge_template_id = ct.id
                    )
                ) AS solve_count
            FROM challenge_templates ct
            LEFT JOIN users u ON ct.creator_id = u.id
            WHERE ct.id = :id
            GROUP BY ct.id, u.username, ct.creator_id
        ");
        $stmt->execute(['id' => $challengeId]);
        $challenge = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$challenge) {
            logWarning("Challenge not found - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("Challenge not found", 404);
        }

        logError($challenge['creator_id']);
        logError($this->userId);

        $challenge['isCreator'] = ($challenge['creator_id'] == $this->userId);
        unset($challenge['creator_id']);

        return $challenge;
    }

    private function getChallengeStatus(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT 
            CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM users u
                    JOIN challenges c ON u.running_challenge = c.id
                    WHERE u.id = :user_id
                    AND c.challenge_template_id = :challenge_id
                ) THEN 'running'
                
                WHEN (
                    SELECT COUNT(DISTINCT cf.id) 
                    FROM challenge_flags cf
                    WHERE cf.challenge_template_id = :challenge_id
                ) = (
                    SELECT COUNT(DISTINCT cc.flag_id) 
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    AND cc.challenge_template_id = :challenge_id
                    AND cf.challenge_template_id = :challenge_id
                ) THEN 'solved'
                
                WHEN EXISTS (
                    SELECT 1 FROM completed_challenges
                    WHERE user_id = :user_id
                    AND challenge_template_id = :challenge_id
                    AND completed_at IS NOT NULL
                ) AND (
                    SELECT COUNT(DISTINCT cf.id) 
                    FROM challenge_flags cf
                    WHERE cf.challenge_template_id = :challenge_id
                ) > (
                    SELECT COUNT(DISTINCT cc.flag_id) 
                    FROM completed_challenges cc
                    JOIN challenge_flags cf ON cc.flag_id = cf.id
                    WHERE cc.user_id = :user_id
                    AND cc.challenge_template_id = :challenge_id
                    AND cf.challenge_template_id = :challenge_id
                ) THEN 'failed'
                
                ELSE 'not_tried'
            END AS challenge_status
            FROM users
            WHERE id = :user_id
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function getChallengeSolution($challengeId, $isSolved)
    {
        if ($isSolved) {
            $stmt = $this->pdo->prepare("
            SELECT
                solution
            FROM challenge_templates
            WHERE id = :challenge_template_id
            ");
            $stmt->execute(['challenge_template_id' => $challengeId]);
            $solution = $stmt->fetch(PDO::FETCH_ASSOC);
            return $solution['solution'];
        }
        return "";
    }

    private function getRemainingSecondsForChallenge(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT EXTRACT(EPOCH FROM (c.expires_at - NOW()))::integer AS remaining_seconds
            FROM challenges c
            JOIN users u ON u.running_challenge = c.id
            WHERE u.id = :user_id
            AND c.challenge_template_id = :challenge_id
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);

        $result = $stmt->fetchColumn();
        return $result !== false ? max(0, $result) : 0;
    }

    private function getRemainingExtensionsForChallenge(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT used_extensions
            FROM challenges c
            JOIN users u ON u.running_challenge = c.id
            WHERE u.id = :user_id
            AND c.challenge_template_id = :challenge_id
        ");
        $stmt->execute([
            'user_id' => $this->userId,
            'challenge_id' => $challengeId
        ]);

        $result = $stmt->fetchColumn();
        return $result !== false ? max(0, $this->config['challenge']['MAX_TIME_EXTENSIONS'] - $result) : 0;
    }

    private function getChallengeFlags(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM challenge_flags 
            WHERE challenge_template_id = :id
            ORDER BY order_index ASC
        ");
        $stmt->execute(['id' => $challengeId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function calculateChallengePoints(array $flags): int
    {
        $totalPoints = 0;
        foreach ($flags as $flag) {
            $totalPoints += (int)($flag['points'] ?? 0);
        }
        return $totalPoints;
    }

    private function getChallengeHints(int $challengeId, int $userPoints)
    {
        $stmt = $this->pdo->prepare("
        SELECT * FROM challenge_hints 
        WHERE challenge_template_id = :id
          AND unlock_points <= :userPoints
        ORDER BY order_index ASC
    ");
        $stmt->execute([
            'id' => $challengeId,
            'userPoints' => $userPoints
        ]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }


    private function getCompletedFlagIds(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT flag_id FROM completed_challenges
            WHERE user_id = :user_id AND challenge_template_id = :challenge_id
            AND flag_id IS NOT NULL
        ");
        $stmt->execute(['user_id' => $this->userId, 'challenge_id' => $challengeId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    private function calculateUserPoints(array $flags, array $completedFlagIds)
    {
        $userPoints = 0;
        foreach ($flags as $flag) {
            if (in_array($flag['id'], $completedFlagIds)) {
                $userPoints += $flag['points'];
            }
        }
        return $userPoints;
    }

    private function getEntrypointsIfRunning(array $challengeStatus)
    {
        if ($challengeStatus['challenge_status'] !== 'running') {
            return [];
        }

        $stmt = $this->pdo->prepare("
            SELECT DISTINCT n.subnet 
            FROM users u
            JOIN machines m ON u.running_challenge = m.challenge_id
            JOIN network_connections nc ON m.id = nc.machine_id
            JOIN networks n ON nc.network_id = n.id
            JOIN network_templates nt ON n.network_template_id = nt.id
            WHERE u.id = :user_id
            AND nt.accessible = TRUE
        ");
        $stmt->execute(['user_id' => $this->userId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }

    private function checkBadgeUnlocks(int $challengeId)
    {
        $unlockedBadges = [];

        try {
            $challengeCategory = $this->getChallengeCategory($challengeId);

            if ($this->isFirstBlood($challengeId) && $this->grantBadge(7)) {
                $unlockedBadges[] = 'First Blood';
                logDebug("First Blood badge unlocked - Challenge ID: {$challengeId}, User ID: {$this->userId}");
            }

            if ($this->isSpeedRunner($challengeId) && $this->grantBadge(8)) {
                $unlockedBadges[] = 'Speed Runner';
                logDebug("Speed Runner badge unlocked - Challenge ID: {$challengeId}, User ID: {$this->userId}");
            }

            $categoryBadge = $this->checkCategoryBadge($challengeCategory);
            if ($categoryBadge) {
                $unlockedBadges[] = $categoryBadge;
                logDebug("Category badge unlocked - Challenge ID: {$challengeId}, User ID: {$this->userId}, Badge: {$categoryBadge}");
            }

            if ($this->isMasterHacker() && $this->grantBadge(9)) {
                $unlockedBadges[] = 'Master Hacker';
                logDebug("Master Hacker badge unlocked - User ID: {$this->userId}");
            }

            return $unlockedBadges;
        } catch (Exception $e) {
            logError("Error checking badge unlocks - Challenge ID: {$challengeId}, User ID: {$this->userId}, Error: " . $e->getMessage());
            throw new Exception('Failed to check badge unlocks', 500);
        }
    }

    private function getChallengeCategory(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT category FROM challenge_templates WHERE id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
        $category = $stmt->fetchColumn();

        if ($category === false) {
            logWarning("Challenge category not found - ID: {$challengeId}, User ID: {$this->userId}");
            throw new Exception("Challenge not found", 404);
        }

        return strtolower($category);
    }

    private function isFirstBlood(int $challengeId)
    {
        $stmt = $this->pdo->prepare("
            SELECT NOT EXISTS (
                SELECT 1 FROM (
                    SELECT DISTINCT cc.user_id
                    FROM completed_challenges cc
                    WHERE cc.challenge_template_id = :challenge_id
                    AND cc.user_id != :user_id
                    GROUP BY cc.user_id
                    HAVING COUNT(DISTINCT cc.flag_id) = (
                        SELECT COUNT(*) 
                        FROM challenge_flags 
                        WHERE challenge_template_id = :challenge_id
                    )
                ) AS is_first_blood)
        ");
        $stmt->execute([
            'challenge_id' => $challengeId,
            'user_id' => $this->userId
        ]);
        return (bool)$stmt->fetchColumn();
    }

    private function isSpeedRunner(int $challengeId)
    {
        $elapsedSeconds = getElapsedSecondsForChallenge($this->pdo,$this->userId,$challengeId);
        return $elapsedSeconds <= 300;
    }

    private function checkCategoryBadge(string $challengeCategory)
    {
        $categoryBadges = [
            'web' => ['id' => 1, 'name' => 'Web Warrior'],
            'crypto' => ['id' => 2, 'name' => 'Crypto Expert'],
            'reverse' => ['id' => 3, 'name' => 'Reverse Engineer'],
            'forensic' => ['id' => 4, 'name' => 'Forensic Analyst'],
            'pwn' => ['id' => 5, 'name' => 'Binary Buster'],
            'misc' => ['id' => 6, 'name' => 'Puzzle Master'],
        ];

        if (!isset($categoryBadges[$challengeCategory])) {
            return null;
        }

        $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT ct.id)
            FROM challenge_templates ct
            JOIN (
                SELECT cc.challenge_template_id
                FROM completed_challenges cc
                WHERE cc.user_id = :user_id
                GROUP BY cc.challenge_template_id
                HAVING COUNT(DISTINCT cc.flag_id) = (
                    SELECT COUNT(*) 
                    FROM challenge_flags 
                    WHERE challenge_template_id = cc.challenge_template_id
                )
            ) solved ON ct.id = solved.challenge_template_id
            WHERE ct.category::text ILIKE :category
        ");
        $stmt->execute(['user_id' => $this->userId, 'category' => $challengeCategory]);

        return ($stmt->fetchColumn() >= 5) && $this->grantBadge($categoryBadges[$challengeCategory]['id'])
            ? $categoryBadges[$challengeCategory]['name']
            : null;
    }

    private function isMasterHacker()
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT b.id) FROM badges b
            LEFT JOIN user_badges ub ON b.id = ub.badge_id AND ub.user_id = :user_id
            WHERE b.id != 6 AND ub.user_id IS NULL
        ");
        $stmt->execute(['user_id' => $this->userId]);
        return $stmt->fetchColumn() == 0;
    }

    private function grantBadge(int $badgeId)
    {
        $stmt = $this->pdo->prepare("SELECT 1 FROM badges WHERE id = :badge_id");
        $stmt->execute(['badge_id' => $badgeId]);
        if (!$stmt->fetch()) {
            logWarning("Attempt to grant non-existent badge - Badge ID: {$badgeId}, User ID: {$this->userId}");
            return false;
        }

        $stmt = $this->pdo->prepare("
            SELECT 1 FROM user_badges 
            WHERE user_id = :user_id AND badge_id = :badge_id
        ");
        $stmt->execute(['user_id' => $this->userId, 'badge_id' => $badgeId]);

        if (!$stmt->fetch()) {
            $stmt = $this->pdo->prepare("
                INSERT INTO user_badges (user_id, badge_id, earned_at)
                VALUES (:user_id, :badge_id, NOW())
            ");
            $stmt->execute(['user_id' => $this->userId, 'badge_id' => $badgeId]);
            logDebug("Badge granted - Badge ID: {$badgeId}, User ID: {$this->userId}");
            return true;
        } else {
            return false;
        }
    }

    private function handleTimeExtension(int $challengeId)
    {
        $this->pdo->beginTransaction();

        try {

            $stmt = $this->pdo->prepare("
                SELECT 
                    c.id,
                    c.used_extensions
                FROM challenges c
                JOIN users u ON u.running_challenge = c.id
                WHERE u.id = :user_id
                AND c.challenge_template_id = :challenge_id
                FOR UPDATE
            ");
            $stmt->execute([
                'user_id' => $this->userId,
                'challenge_id' => $challengeId
            ]);

            $challenge = $stmt->fetch();

            if (!$challenge) {
                logWarning("Attempt to extend non-running challenge - ID: {$challengeId}, User ID: {$this->userId}");
                throw new Exception("You don't have this challenge running", 400);
            }

            if ($challenge['used_extensions'] >= $this->config['challenge']['MAX_TIME_EXTENSIONS']) {
                logWarning("Attempt to extend challenge without used_extensions left - ID: {$challengeId}, User ID: {$this->userId}");
                throw new Exception("You cannot extend this challenge any longer", 400);
            }

            $stmt = $this->pdo->prepare("
                UPDATE challenges
                SET 
                    expires_at = NOW() + (:extend_scalar * INTERVAL '1 hour'),
                    used_extensions = used_extensions + 1
                WHERE id = :challenge_id
            ");
            $stmt->execute([
                'challenge_id' => $challenge['id'],
                'extend_scalar' => $this->config['challenge']['EXTENSION_HOURS']
            ]);

            $remainingSeconds = $this->getRemainingSecondsForChallenge($challengeId);
            $remainingExtensions = $this->getRemainingExtensionsForChallenge($challengeId);

            $this->pdo->commit();
            logDebug("Challenge time extended - ID: {$challengeId}, User ID: {$this->userId}");

            $this->sendResponse([
                'success' => true,
                'message' => 'Challenge time extended by 1 hour',
                'remaining_seconds' => $remainingSeconds,
                'remaining_extensions' => $remainingExtensions
            ]);
        } catch (Exception $e) {
            $this->pdo->rollBack();
            logError("Failed to extend challenge time - ID: {$challengeId}, Error: " . $e->getMessage());
            throw $e;
        }
    }

    private function handleError(Exception $e)
    {
        $errorCode = $e->getCode() ?: 500;
        http_response_code($errorCode);

        $response = [
            'success' => false,
            'message' => $e->getMessage(),
            'error_code' => $errorCode
        ];

        if ($errorCode === 400) {
            $response['error_details'] = [
                'allowed_actions' => $this->config['challenge']['ALLOWED_ACTIONS']
            ];
        }

        logError("ChallengeAPI error [{$errorCode}]: " . $e->getMessage());
        $this->sendResponse($response);
    }

    private function sendResponse(array $response)
    {
        echo json_encode($response);
    }
}

try {
    $api = new ChallengeHandler($config);
    $api->handleRequest();
} catch (Exception $e) {
    $errorCode = (int)($e->getCode() ?: 500);
    http_response_code($errorCode);
    logError("Error in challenge endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}