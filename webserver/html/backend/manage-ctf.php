<?php
declare(strict_types=1);

use JetBrains\PhpStorm\NoReturn;

require_once __DIR__ . '/../includes/logger.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/curlHelper.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/challengeHelper.php';
$config = require __DIR__ . '/../config/backend.config.php';
$generalConfig = json_decode(file_get_contents(__DIR__ . '/../config/general.config.json'), true);

class CTFManagementHandler
{
    private PDO $pdo;
    private int $userId;
    private string $method;
    private array $inputData;
    private array $config;
    private array $generalConfig;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;
    private IAuthHelper $authHelper;
    private ICurlHelper $curlHelper;
    private IChallengeHelper $challengeHelper;

    private array $session;
    private array $server;
    private array $get;
    private array $post;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,
        array $generalConfig,
        IDatabaseHelper $databaseHelper = new DatabaseHelper(),
        ISecurityHelper $securityHelper = new SecurityHelper(),
        ILogger $logger = new Logger(),
        IAuthHelper $authHelper = new AuthHelper(),
        ICurlHelper $curlHelper = new CurlHelper(),
        IChallengeHelper $challengeHelper = new ChallengeHelper(),
        array $session = null,
        array $server = null,
        array $get = null,
        array $post = null
    )
    {
        if($session)
            $this->session =& $session;
        else
            $this->session =& $_SESSION;

        $this->server = $server ?? $_SERVER;
        $this->get = $get ?? $_GET;
        $this->post = $post ?? $_POST;

        $this->databaseHelper = $databaseHelper;
        $this->securityHelper = $securityHelper;
        $this->logger = $logger;
        $this->authHelper = $authHelper;
        $this->curlHelper = $curlHelper;
        $this->challengeHelper = $challengeHelper;

        $this->config = $config;
        $this->generalConfig = $generalConfig;
        header('Content-Type: application/json');
        $this->pdo = $this->databaseHelper->getPDO();
        $this->initSession();
        $this->validateAccess();
        $this->userId = $this->session['user_id'];
        $this->method = $this->server['REQUEST_METHOD'];
        $this->inputData = $this->parseInputData();

        $this->logger->logDebug("Initialized CTFManagementHandler for user ID: $this->userId");
    }

    private function initSession(): void
    {
        try {
            $this->securityHelper->initSecureSession();
        } catch (Exception $e) {
            $this->logger->logError("Session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 500);
        }
    }

    /**
     * @throws Exception
     */
    private function validateAccess(): void
    {
        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt to manage CTF - IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new RuntimeException('Unauthorized - Please login', 401);
        }

        $csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token in manage CTF - User ID: " . ($this->session['user_id'] ?? 'unknown') . ", Token: $csrfToken");
            throw new RuntimeException('Invalid CSRF token', 403);
        }

        if (!$this->securityHelper->validateAdminAccess($this->pdo)) {
            $this->logger->logWarning("Non-admin access attempt to manage CTF - User ID: " . ($this->session['user_id'] ?? 'unknown'));
            throw new Exception('Unauthorized - Admin access only', 403);
        }
    }

    private function parseInputData(): array
    {
        if ($this->method === 'GET') {
            return $this->get;
        }

        if ($this->method === 'DELETE') {
            $data = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid JSON in CTF deletion - User ID: $this->userId");
                throw new RuntimeException('Invalid JSON data', 400);
            }
            return $data;
        }

        return $this->post;
    }

    public function handleRequest(): void
    {
        try {
            switch ($this->method) {
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
                    $this->logger->logWarning("Invalid method in manage CTF - Method: $this->method, User ID: $this->userId");
                    throw new RuntimeException('Method not allowed', 405);
            }
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function handleGetRequest(): void
    {
        $action = $this->inputData['action'] ?? null;

        switch($action) {
            case 'get_challenges':
                $this->handleGetChallenges();
                break;
            case 'get_leaderboard':
                $this->handleLeaderboard();
                break;
            default:
                $this->handleGetChallenges();
        }
    }

    private function handleGetChallenges(): void
    {
        $challenges = $this->getChallenges();
        $stats = $this->getChallengeStats();

        echo json_encode([
            'success' => true,
            'challenges' => $challenges,
            'stats' => $stats
        ]);
    }

    private function handleLeaderboard(): void
   {
       if (!isset($this->inputData['id'])) {
           echo json_encode(['success' => false, 'message' => 'Challenge ID is required']);
           exit;
       }

       $challengeId = (int)$this->inputData['id'];
       $page = isset($this->inputData['page']) ? (int)$this->inputData['page'] : 1;
       $limit = isset($this->inputData['limit']) ? (int)$this->inputData['limit'] : 10;
       $offset = ($page - 1) * $limit;

       try {
           $stmt = $this->pdo->prepare("
            SELECT creator_id 
            FROM challenge_templates 
            WHERE id = ?
        ");
           $stmt->execute([$challengeId]);
           $creatorId = $stmt->fetchColumn();

           if ($creatorId !== $this->userId) {
               echo json_encode(['success' => false, 'message' => 'You are not authorized to view this leaderboard']);
               exit;
           }

           $leaderboard = $this->challengeHelper->getChallengeLeaderboard($this->pdo, $challengeId, $limit, $offset);

           $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT cc.user_id) AS total 
            FROM completed_challenges cc
            JOIN challenge_flags cf ON cc.flag_id = cf.id
            WHERE cc.challenge_template_id = ?
            AND cf.points > 0
        ");
           $stmt->execute([$challengeId]);
           $total = $stmt->fetchColumn();

           echo json_encode([
               'success' => true,
               'leaderboard' => $leaderboard,
               'total_entries' => $total
           ]);
       } catch (PDOException) {
           echo json_encode(['success' => false, 'message' => 'Error getting leaderboard']);
       }
   }

    private function handlePostRequest(): void
    {
        $action = $this->inputData['action'] ?? null;

        switch ($action) {
            case 'update_challenge':
                $this->handleUpdateChallenge();
                break;
            case 'restore_challenge':
                $this->handleRestoreRequest();
                break;
            default:
                throw new RuntimeException('Invalid action', 400);
        }
    }

    private function handleUpdateChallenge(): void
    {
        $errors = $this->validateChallengeData();
        if (!empty($errors['errors'])) {
            $this->logger->logWarning("Validation failed in CTF update - User ID: $this->userId, Errors: " . implode(', ', $errors['errors']));
            http_response_code(400);
            echo json_encode($errors);
            exit;
        }

        $challenge = $this->verifyChallengeOwnershipAndStatus((int)$this->inputData['id']);

        if ($challenge['marked_for_deletion'] && !empty($this->inputData['isActive'])) {
            $this->logger->logWarning("Attempt to activate deleted challenge - ID: {$this->inputData['id']}, User ID: $this->userId");
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Cannot activate a challenge marked for deletion. Restore it first.',
                'fields' => ['edit-active']
            ]);
            exit;
        }

        $this->updateChallenge();

        $this->logger->logInfo("CTF challenge updated - ID: {$this->inputData['id']}, Name: {$this->inputData['name']}, User ID: $this->userId");

        echo json_encode([
            'success' => true,
            'message' => 'Challenge updated successfully'
        ]);
    }

    private function handleRestoreRequest(): void
    {
        if (empty($this->inputData['id'])) {
            throw new RuntimeException('Challenge ID is required', 400);
        }

        $challengeId = (int)$this->inputData['id'];
        $challenge = $this->verifyChallengeOwnershipAndStatus($challengeId);

        if (!$challenge['marked_for_deletion']) {
            $this->logger->logWarning("Attempt to restore non-deleted challenge - ID: $challengeId, User ID: $this->userId");
            throw new RuntimeException('Challenge is not marked for deletion', 400);
        }

        $this->restoreChallenge($challengeId);

        $this->logger->logInfo("CTF challenge restored - ID: $challengeId, User ID: $this->userId");

        echo json_encode([
            'success' => true,
            'message' => 'Challenge restored successfully'
        ]);
    }

    private function validateChallengeData(): array
    {
        $errors = ['errors' => [], 'fields' => []];
        $input = $this->inputData;

        if (empty($input['name'])) {
            $errors['errors'][] = 'Challenge name is required';
            $errors['fields'][] = 'edit-name';
        } elseif (strlen($input['name']) > $this->generalConfig['ctf']['MAX_CTF_NAME_LENGTH']) {
            $errors['errors'][] = 'Name cannot exceed ' . $this->generalConfig['ctf']['MAX_CTF_NAME_LENGTH'] . ' characters';
            $errors['fields'][] = 'edit-name';
        } else {
            $stmt = $this->pdo->prepare("
            SELECT id FROM challenge_templates 
            WHERE name = :name 
            AND creator_id = :user_id
            " . (isset($input['id']) ? "AND id != :exclude_id" : "")
            );

            $params = [
                'name' => $input['name'],
                'user_id' => $this->userId
            ];

            if (isset($input['id'])) {
                $params['exclude_id'] = $input['id'];
            }

            $stmt->execute($params);

            if ($stmt->fetch()) {
                $errors['errors'][] = 'A challenge with this name already exists';
                $errors['fields'][] = 'edit-name';
            }
        }

        if (empty($input['description'])) {
            $errors['errors'][] = 'Description is required';
            $errors['fields'][] = 'edit-description';
        } elseif (strlen($input['description']) > $this->generalConfig['ctf']['MAX_CTF_DESCRIPTION_LENGTH']) {
            $errors['errors'][] = 'Description cannot exceed ' . $this->generalConfig['ctf']['MAX_CTF_DESCRIPTION_LENGTH'] . ' characters';
            $errors['fields'][] = 'edit-description';
        }

        if (empty($input['category']) || !in_array($input['category'], $this->config['challenge']['VALID_CATEGORIES'])) {
            $errors['errors'][] = 'Please select a valid category';
            $errors['fields'][] = 'edit-category';
        }

        if (!in_array($input['difficulty'], $this->config['challenge']['VALID_DIFFICULTIES'])) {
            $errors['errors'][] = 'Please select a valid difficulty level';
            $errors['fields'][] = 'edit-difficulty';
        }

        if (strlen($input['hint'] ?? '') > $this->generalConfig['ctf']['MAX_GENERAL_HINT_LENGTH']) {
            $errors['errors'][] = 'Hint cannot exceed ' . $this->generalConfig['ctf']['MAX_GENERAL_HINT_LENGTH'] . ' characters';
            $errors['fields'][] = 'edit-hint';
        }

        if (strlen($input['solution'] ?? '') > $this->generalConfig['ctf']['MAX_SOLUTION_LENGTH']) {
            $errors['errors'][] = 'Solution cannot exceed ' . $this->generalConfig['ctf']['MAX_SOLUTION_LENGTH'] . ' characters';
            $errors['fields'][] = 'edit-solution';
        }

        return $errors;
    }

    private function verifyChallengeOwnershipAndStatus(int $challengeId): array
    {
        $stmt = $this->pdo->prepare("
        SELECT id, marked_for_deletion 
        FROM challenge_templates 
        WHERE id = :id AND creator_id = :user_id
    ");
        $stmt->execute(['id' => $challengeId, 'user_id' => $this->userId]);
        $challenge = $stmt->fetch();

        if (!$challenge) {
            $this->logger->logError("Challenge not found or access denied - Challenge ID: $challengeId, User ID: $this->userId");
            throw new RuntimeException('Challenge not found or access denied', 404);
        }

        return $challenge;
    }

    private function updateChallenge(): void
    {
        $isActive = (int)filter_var($this->inputData['isActive'], FILTER_VALIDATE_BOOLEAN);

        $stmt = $this->pdo->prepare("SELECT marked_for_deletion FROM challenge_templates WHERE id = :id");
        $stmt->execute(['id' => $this->inputData['id']]);
        $challenge = $stmt->fetch();

        if ($challenge['marked_for_deletion']) {
            $isActive = 0;
        }

        $stmt = $this->pdo->prepare("
            UPDATE challenge_templates SET
                name = :name,
                description = :description,
                category = :category,
                difficulty = :difficulty,
                hint = :hint,
                solution = :solution,
                is_active = :is_active,
                updated_at = NOW()
            WHERE id = :id
        ");

        $stmt->execute([
            'id' => $this->inputData['id'],
            'name' => $this->inputData['name'],
            'description' => $this->inputData['description'],
            'category' => $this->inputData['category'],
            'difficulty' => $this->inputData['difficulty'],
            'hint' => !empty($this->inputData['hint']) ? $this->inputData['hint'] : null,
            'solution' => !empty($this->inputData['solution']) ? $this->inputData['solution'] : null,
            'is_active' => $isActive
        ]);
    }

    private function restoreChallenge(int $challengeId): void
    {
        $stmt = $this->pdo->prepare("
        UPDATE challenge_templates 
        SET marked_for_deletion = false, 
            is_active = true
        WHERE id = :challenge_id
    ");
        $stmt->execute(['challenge_id' => $challengeId]);
    }

    /**
     * @throws Exception
     */
    private function handleDeleteRequest(): void
    {
        $challengeId = $this->inputData['id'] ?? null;
        $forceDelete = $this->inputData['force'] ?? false;

        if (!$challengeId) {
            $this->logger->logError("Missing challenge ID in deletion - User ID: $this->userId");
            throw new RuntimeException('Challenge ID is required', 400);
        }

        $challenge = $this->verifyChallengeOwnershipForDeletion((int)$challengeId);
        $this->processDeletion((int)$challengeId, (boolean)$forceDelete, $challenge['name']);
    }

    private function verifyChallengeOwnershipForDeletion(int $challengeId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, name FROM challenge_templates 
            WHERE id = :id AND creator_id = :user_id
        ");
        $stmt->execute(['id' => $challengeId, 'user_id' => $this->userId]);
        $challenge = $stmt->fetch();

        if (!$challenge) {
            $this->logger->logError("Challenge not found or access denied - Challenge ID: $challengeId, User ID: $this->userId");
            throw new RuntimeException('Challenge not found or access denied', 404);
        }

        return $challenge;
    }

    /**
     * @throws Exception
     */
    private function processDeletion(int $challengeId, bool $forceDelete, string $challengeName): void
    {
        $this->pdo->beginTransaction();

        try {
            if ($forceDelete) {
                $this->forceDeleteChallenge($challengeId);
                $message = 'Challenge and all instances permanently deleted';
                $this->logger->logInfo("Force deleted challenge - ID: $challengeId, Name: '$challengeName'");
            } else {
                $message = $this->softDeleteChallenge($challengeId);
                $this->logger->logInfo("Soft deleted challenge - ID: $challengeId, Name: '$challengeName'");
            }

            $this->pdo->commit();

            echo json_encode([
                'success' => true,
                'message' => $message
            ]);
        } catch (Exception $e) {
            $this->pdo->rollBack();
            $this->logger->logError("Failed to delete CTF challenge - ID: $challengeId, Name: '$challengeName', Error: " . $e->getMessage());
            throw $e;
        }
    }

    private function forceDeleteChallenge(int $challengeId): void
    {

        $this->markChallengeForDeletion($challengeId);
        $this->stopRunningInstances($challengeId);
        $this->deleteCompletedChallenges($challengeId);
        $this->deleteVmTemplates($challengeId);
        $this->deleteRelatedDatabaseEntries($challengeId);
    }

    private function markChallengeForDeletion(int $challengeId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE challenge_templates 
            SET marked_for_deletion = true 
            WHERE id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
    }

    private function stopRunningInstances(int $challengeId): void
    {
        $stmt = $this->pdo->prepare("
            SELECT u.id AS user_id, c.id AS challenge_id
            FROM users u
            JOIN challenges c ON u.running_challenge = c.id
            WHERE c.challenge_template_id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
        $runningInstances = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($runningInstances as $instance) {
            $response = $this->curlHelper->makeBackendRequest(
                '/stop-challenge',
                'POST',
                $this->authHelper->getBackendHeaders(),
                ['user_id' => $instance['user_id']]
            );

            if (!$response['success']) {
                throw new RuntimeException('Failed to stop challenge instance: ' . ($response['error'] ?? $response['response']));
            }
        }
    }

    private function deleteCompletedChallenges(int $challengeId): void
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM completed_challenges 
            WHERE challenge_template_id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
    }

    private function deleteVmTemplates(int $challengeId): void
    {
        $response = $this->curlHelper->makeBackendRequest(
            '/delete-machine-templates',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['challenge_id' => $challengeId]
        );

        if (!$response['success']) {
            throw new RuntimeException('Failed to delete VM templates: ' . ($response['error'] ?? $response['response']));
        }
    }

    private function deleteRelatedDatabaseEntries(int $challengeId): void
    {
        $tables = [
            'challenge_flags',
            'challenge_hints',
            'network_connection_templates',
            'machine_templates',
            'network_templates',
            'challenge_templates'
        ];

        foreach ($tables as $table) {
            $stmt = match ($table) {
                'network_connection_templates' => $this->pdo->prepare("
                        DELETE FROM network_connection_templates
                        WHERE machine_template_id IN (
                            SELECT id FROM machine_templates 
                            WHERE challenge_template_id = :challenge_id
                        )
                    "),
                'machine_templates' => $this->pdo->prepare("
                        DELETE FROM machine_templates 
                        WHERE challenge_template_id = :challenge_id
                    "),
                'network_templates' => $this->pdo->prepare("
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
                    "),
                'challenge_templates' => $this->pdo->prepare("
                        DELETE FROM challenge_templates 
                        WHERE id = :challenge_id
                    "),
                default => $this->pdo->prepare("
                        DELETE FROM $table 
                        WHERE challenge_template_id = :challenge_id
                    "),
            };

            $stmt->execute(['challenge_id' => $challengeId]);
        }
    }

    private function softDeleteChallenge(int $challengeId): string
    {
        $activeDeployments = $this->countActiveDeployments($challengeId);

        if ($activeDeployments > 0) {
            $this->markChallengeForSoftDeletion($challengeId);
            return 'Challenge marked for deletion (will be removed when all instances complete)';
        }

        $this->deleteCompletedChallenges($challengeId);
        $this->deleteVmTemplates($challengeId);
        $this->deleteRelatedDatabaseEntries($challengeId);
        return 'Challenge deleted successfully (no active instances)';
    }

    private function countActiveDeployments(int $challengeId): int
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(c.id) AS active_count
            FROM challenges c
            JOIN users u ON u.running_challenge = c.id
            WHERE c.challenge_template_id = :challenge_id
            AND u.running_challenge IS NOT NULL
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
        return $stmt->fetchColumn();
    }

    private function markChallengeForSoftDeletion(int $challengeId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE challenge_templates 
            SET marked_for_deletion = true, 
                is_active = false
            WHERE id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeId]);
    }

    private function getChallenges(): array
    {
        $stmt = $this->pdo->prepare($this->getChallengesQuery());
        $stmt->execute(['user_id' => $this->userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function getChallengesQuery(): string
    {
        return "
            WITH flag_counts AS (
                SELECT
                    challenge_template_id,
                    COUNT(id) AS total_flags
                FROM challenge_flags
                GROUP BY challenge_template_id
            ),
            user_flags AS (
                SELECT
                    challenge_template_id,
                    user_id,
                    flag_id,
                    MAX(completed_at) AS flag_found_at
                FROM completed_challenges
                WHERE flag_id IS NOT NULL AND completed_at IS NOT NULL
                GROUP BY challenge_template_id, user_id, flag_id
            ),
            fully_solved AS (
                SELECT
                    uf.challenge_template_id,
                    uf.user_id,
                    COUNT(DISTINCT uf.flag_id) AS found_flags,
                    MAX(uf.flag_found_at) AS last_flag_time
                FROM user_flags uf
                GROUP BY uf.challenge_template_id, uf.user_id
            ),
            valid_attempts AS (
                SELECT
                    cc.challenge_template_id,
                    cc.user_id,
                    cc.started_at,
                    cc.completed_at,
                    EXTRACT(EPOCH FROM (cc.completed_at - cc.started_at))/60 AS duration_minutes
                FROM completed_challenges cc
                WHERE cc.started_at IS NOT NULL AND cc.completed_at IS NOT NULL
                AND EXTRACT(EPOCH FROM (cc.completed_at - cc.started_at)) > 10
            ),
            pre_completion_attempts AS (
                SELECT
                    va.challenge_template_id,
                    va.user_id,
                    va.started_at,
                    va.completed_at,
                    va.duration_minutes
                FROM valid_attempts va
                JOIN fully_solved fs ON
                    fs.challenge_template_id = va.challenge_template_id AND
                    fs.user_id = va.user_id
                WHERE va.completed_at <= fs.last_flag_time
            ),
            aggregated_times AS (
                SELECT
                    challenge_template_id,
                    user_id,
                    SUM(duration_minutes) AS total_duration
                FROM pre_completion_attempts
                GROUP BY challenge_template_id, user_id
            ),
            solved_stats AS (
                SELECT
                    challenge_template_id,
                    COUNT(*) AS solve_count,
                    ROUND(AVG(total_duration)) AS avg_completion_minutes
                FROM aggregated_times
                GROUP BY challenge_template_id
            ),
            active_deployments AS (
                SELECT
                    c.challenge_template_id,
                    COUNT(DISTINCT c.id) AS active_count
                FROM challenges c
                JOIN users u ON u.running_challenge = c.id
                WHERE u.running_challenge IS NOT NULL
                GROUP BY c.challenge_template_id
            ),
            real_deployments AS (
                SELECT
                    challenge_template_id,
                    COUNT(*) AS total_count
                FROM completed_challenges
                WHERE EXTRACT(EPOCH FROM (completed_at - started_at)) > 10
                OR completed_at IS NULL
                GROUP BY challenge_template_id
            )
            SELECT
                ct.id,
                ct.name,
                ct.description,
                ct.category,
                ct.difficulty,
                ct.image_path,
                ct.is_active,
                ct.created_at,
                ct.marked_for_deletion,
                COALESCE(rd.total_count, 0) AS total_deployments,
                ct.hint,
                ct.solution,
                COALESCE(ad.active_count, 0) AS active_deployments,
                COALESCE(ss.solve_count, 0) AS solve_count,
                COALESCE(ss.avg_completion_minutes, 0) AS avg_completion_minutes
            FROM challenge_templates ct
            LEFT JOIN solved_stats ss ON ss.challenge_template_id = ct.id
            LEFT JOIN active_deployments ad ON ad.challenge_template_id = ct.id
            LEFT JOIN real_deployments rd ON rd.challenge_template_id = ct.id
            WHERE ct.creator_id = :user_id
            ORDER BY ct.created_at DESC
        ";
    }

    private function getChallengeStats(): array
    {
        $stats = [];

        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM challenge_templates WHERE creator_id = :user_id");
        $stmt->execute(['user_id' => $this->userId]);
        $stats['total_challenges'] = $stmt->fetchColumn();

        $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT c.id) 
            FROM challenges c
            JOIN users u ON u.running_challenge = c.id
            JOIN challenge_templates ct ON c.challenge_template_id = ct.id
            WHERE ct.creator_id = :user_id AND u.running_challenge IS NOT NULL
        ");
        $stmt->execute(['user_id' => $this->userId]);
        $stats['active_deployments'] = $stmt->fetchColumn();

        $stmt = $this->pdo->prepare("
            SELECT COALESCE(SUM(total_count), 0)
            FROM (
                SELECT challenge_template_id, COUNT(*) AS total_count
                FROM completed_challenges
                WHERE EXTRACT(EPOCH FROM (completed_at - started_at)) > 2 OR completed_at IS NULL
                GROUP BY challenge_template_id
            ) rd
            JOIN challenge_templates ct ON rd.challenge_template_id = ct.id
            WHERE ct.creator_id = :user_id
        ");
        $stmt->execute(['user_id' => $this->userId]);
        $stats['total_deployments'] = $stmt->fetchColumn();

        $stmt = $this->pdo->prepare($this->getAvgCompletionTimeQuery());
        $stmt->execute(['user_id' => $this->userId]);
        $stats['avg_completion_minutes'] = $stmt->fetchColumn();

        return $stats;
    }

    private function getAvgCompletionTimeQuery(): string
    {
        return "
            WITH flag_counts AS (
                SELECT challenge_template_id, COUNT(*) AS total_flags
                FROM challenge_flags
                GROUP BY challenge_template_id
            ),
            user_flag_completions AS (
                SELECT
                    cc.challenge_template_id,
                    cc.user_id,
                    COUNT(DISTINCT cc.flag_id) AS flags_found,
                    MAX(cc.completed_at) AS last_flag_time
                FROM completed_challenges cc
                GROUP BY cc.challenge_template_id, cc.user_id
            ),
            successful_users AS (
                SELECT
                    ufc.challenge_template_id,
                    ufc.user_id,
                    ufc.last_flag_time
                FROM user_flag_completions ufc
                JOIN flag_counts fc ON ufc.challenge_template_id = fc.challenge_template_id
                WHERE ufc.flags_found = fc.total_flags
            ),
            valid_sessions AS (
                SELECT
                    cc.challenge_template_id,
                    cc.user_id,
                    cc.started_at,
                    cc.completed_at,
                    EXTRACT(EPOCH FROM (cc.completed_at - cc.started_at))/60 AS duration_minutes,
                    su.last_flag_time
                FROM completed_challenges cc
                JOIN successful_users su ON cc.challenge_template_id = su.challenge_template_id AND cc.user_id = su.user_id
                WHERE cc.started_at < su.last_flag_time
            ),
            avg_times AS (
                SELECT
                    challenge_template_id,
                    user_id,
                    SUM(duration_minutes) AS total_duration
                FROM valid_sessions
                GROUP BY challenge_template_id, user_id
            )
            SELECT COALESCE(ROUND(AVG(total_duration)), 0) AS avg_completion_minutes
            FROM avg_times
            JOIN challenge_templates ct ON avg_times.challenge_template_id = ct.id
            WHERE ct.creator_id = :user_id
        ";
    }

    #[NoReturn] private function handleError(Exception $e): void
    {
        $errorCode = $e->getCode() ?: 500;
        $errorMessage = $errorCode >= 500 ? 'An internal server error occurred' : $e->getMessage();

        if ($errorCode === 401) {
            session_unset();
            session_destroy();
            $this->logger->logWarning("Session destroyed due to unauthorized access");
        }

        if ($errorCode >= 500) {
            $this->logger->logError("Internal error in CTF management: " . $e->getMessage() . "\n" . $e->getTraceAsString());
        } else {
            $this->logger->logWarning("CTF management error: " . $e->getMessage());
        }

        http_response_code($errorCode);
        echo json_encode([
            'success' => false,
            'message' => $errorMessage,
            'redirect' => $errorCode === 401 ? '/login' : null
        ]);
        exit;
    }
}

try {
    $handler = new CTFManagementHandler($config, $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $this->logger->logError("Error in manage-ctf endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}