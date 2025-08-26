<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class ExploreHandler
{
    private PDO $pdo;
    private ?int $userId;
    private bool $isPublic = true;
    private array $config;
    private int $perPage = 12;

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
        $this->userId = $this->session['user_id'] ?? null;
        $this->logger->logDebug("Initialized ExploreHandler for user ID: " . ($this->userId ?? 'guest'));
    }

    /**
     * @throws Exception
     */
    private function initSession(): void
    {
        $this->securityHelper->initSecureSession();

        if (!$this->isPublic && !$this->securityHelper->validateSession()) {
            $this->logger->logWarning('Unauthorized access attempt to explore route');
            throw new Exception('Unauthorized - Please login', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateRequest(): void
    {
        if (!$this->isPublic) {
            $csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
            if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
                $this->logger->logWarning('Invalid CSRF token attempt from user: ' . ($this->session['user_id'] ?? 'unknown'));
                throw new Exception('Invalid CSRF token.', 403);
            }
        }
    }

    /**
     * @throws Exception
     */
    public function handleRequest(): void
    {
        try {
            $params = $this->parseInputParameters();
            $challenges = $this->fetchChallenges($params);
            $response = $this->buildResponse($challenges, $params);

            $this->sendResponse($response);
        } catch (PDOException $e) {
            $this->logger->logError("Database error in explore route: " . $e->getMessage());
            throw new Exception('Failed to retrieve challenges', 500);
        }
    }

    private function parseInputParameters(): array
    {
        $search = $this->get['search'] ?? '';
        $category = $this->get['category'] ?? 'all';
        $difficulty = $this->get['difficulty'] ?? 'all';
        $sort = $this->get['sort'] ?? 'popularity';
        $page = isset($this->get['page']) ? (int)$this->get['page'] : 1;

        if (!in_array($category, $this->config['filters']['CHALLENGE_CATEGORIES'])) {
            $this->logger->logDebug("Invalid category requested: $category - Defaulting to 'all'");
            $category = 'all';
        }

        if (!in_array($difficulty, $this->config['filters']['CHALLENGE_DIFFICULTIES'])) {
            $this->logger->logDebug("Invalid difficulty requested: $difficulty - Defaulting to 'all'");
            $difficulty = 'all';
        }

        if (!in_array($sort, $this->config['sorts']['VALID'])) {
            $this->logger->logDebug("Invalid sort requested: $sort - Defaulting to 'popularity'");
            $sort = 'popularity';
        }

        if ($page < 1) {
            $this->logger->logDebug("Invalid page number requested: $page - Defaulting to 1");
            $page = 1;
        }

        $search_param = !empty($search) ? "%$search%" : '';

        return [
            'search' => $search,
            'search_param' => $search_param,
            'category' => $category,
            'difficulty' => $difficulty,
            'sort' => $sort,
            'page' => $page
        ];
    }

    private function fetchChallenges($params): array
    {
        $query = $this->buildBaseQuery();
        $whereConditions = $this->buildWhereConditions($params);
        $params['limit'] = $this->perPage;
        $params['offset'] = ($params['page'] - 1) * $this->perPage;

        if (!empty($whereConditions)) {
            $query .= " WHERE " . implode(" AND ", $whereConditions);
        }

        $query .= $this->buildGroupBy();
        $query .= $this->buildOrderBy($params['sort']);

        $countQuery = "SELECT COUNT(*) FROM ($query) AS total";
        $countStmt = $this->pdo->prepare($countQuery);
        $this->bindCommonParams($countStmt, $params);
        $countStmt->execute();
        $totalItems = (int)$countStmt->fetchColumn();

        $query .= " LIMIT :limit OFFSET :offset";
        $stmt = $this->pdo->prepare($query);
        $this->bindCommonParams($stmt, $params);
        $stmt->bindValue(':limit', $params['limit'], PDO::PARAM_INT);
        $stmt->bindValue(':offset', $params['offset'], PDO::PARAM_INT);
        $stmt->execute();

        $challenges = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'data' => $challenges,
            'total_items' => $totalItems,
            'current_page' => $params['page'],
            'total_pages' => ceil($totalItems / $this->perPage)
        ];
    }

    private function buildBaseQuery(): string
    {
        return "
WITH user_completed_flags AS (
    SELECT 
        user_id,
        challenge_template_id,
        flag_id
    FROM completed_challenges
),
challenge_total_flags AS (
    SELECT 
        challenge_template_id, 
        COUNT(*) as total_flags
    FROM challenge_flags
    GROUP BY challenge_template_id
),
user_solved_challenges AS (
    SELECT 
        ucf.user_id,
        ucf.challenge_template_id
    FROM user_completed_flags ucf
    JOIN challenge_total_flags ctf ON ucf.challenge_template_id = ctf.challenge_template_id
    GROUP BY ucf.user_id, ucf.challenge_template_id
    HAVING COUNT(DISTINCT ucf.flag_id) = MAX(ctf.total_flags)
)
SELECT 
    ct.id,
    ct.name,
    ct.description,
    ct.category,
    ct.difficulty,
    ct.created_at,
    ct.image_path,
    ct.is_active,
    COUNT(DISTINCT usc.user_id) AS solved_count,
    COUNT(DISTINCT cc.user_id) AS attempted_count
FROM challenge_templates ct
LEFT JOIN user_solved_challenges usc ON usc.challenge_template_id = ct.id
LEFT JOIN completed_challenges cc ON cc.challenge_template_id = ct.id";
    }

    private function buildWhereConditions($params): array
    {
        $conditions = [];

        if ($params['category'] !== 'all') {
            $conditions[] = "ct.category = :category";
        }

        if ($params['difficulty'] !== 'all') {
            $conditions[] = "ct.difficulty = :difficulty";
        }

        if (!empty($params['search'])) {
            $conditions[] = "(ct.name ILIKE :search OR ct.description ILIKE :search)";
        }

        return $conditions;
    }

    private function buildGroupBy(): string
    {
        return " GROUP BY ct.id, ct.name, ct.description, ct.category, ct.difficulty, ct.created_at, ct.image_path";
    }

    private function buildOrderBy($sort): string
    {
        return match ($sort) {
            'date' => " ORDER BY ct.created_at DESC",
            'difficulty' => " ORDER BY 
                    CASE ct.difficulty
                        WHEN 'easy' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'hard' THEN 3
                        ELSE 0
                    END",
            default => " ORDER BY solved_count DESC, attempted_count DESC",
        };
    }

    private function bindCommonParams($stmt, $params): void
    {
        if ($params['category'] !== 'all') {
            $stmt->bindValue(':category', $params['category']);
        }

        if ($params['difficulty'] !== 'all') {
            $stmt->bindValue(':difficulty', $params['difficulty']);
        }

        if (!empty($params['search'])) {
            $stmt->bindValue(':search', $params['search_param']);
        }
    }

    private function buildResponse($challenges, $params): array
    {
        $formattedChallenges = array_map([$this, 'formatChallenge'], $challenges['data']);

        return [
            'challenges' => $formattedChallenges,
            'pagination' => [
                'current_page' => $challenges['current_page'],
                'total_pages' => $challenges['total_pages'],
                'total_items' => $challenges['total_items'],
                'per_page' => $this->perPage
            ],
            'filters' => [
                'search' => htmlspecialchars($params['search'], ENT_QUOTES, 'UTF-8'),
                'category' => htmlspecialchars($params['category'], ENT_QUOTES, 'UTF-8'),
                'difficulty' => htmlspecialchars($params['difficulty'], ENT_QUOTES, 'UTF-8'),
                'sort' => htmlspecialchars($params['sort'], ENT_QUOTES, 'UTF-8')
            ]
        ];
    }

    private function formatChallenge($challenge): array
    {
        $solvedStatus = $this->userId ? $this->getUserChallengeData($challenge['id']) : null;

        return [
            'id' => (int)$challenge['id'],
            'title' => htmlspecialchars($challenge['name'], ENT_QUOTES, 'UTF-8'),
            'description' => htmlspecialchars($challenge['description'], ENT_QUOTES, 'UTF-8'),
            'category' => htmlspecialchars($challenge['category'], ENT_QUOTES, 'UTF-8'),
            'difficulty' => htmlspecialchars($challenge['difficulty'], ENT_QUOTES, 'UTF-8'),
            'image' => htmlspecialchars($challenge['image_path'] ?? '../assets/images/ctf-default.png', ENT_QUOTES, 'UTF-8'),
            'created_at' => $challenge['created_at'],
            'is_active' => $challenge['is_active'],
            'solved' => $solvedStatus === null ? null : (bool)$solvedStatus
        ];
    }

    private function getUserChallengeData($challengeId)
    {
        try {
            $stmt = $this->pdo->prepare("
            WITH challenge_total_points AS (
                SELECT 
                    challenge_template_id,
                    SUM(points) AS total_points
                FROM challenge_flags
                GROUP BY challenge_template_id
            ),
            user_completed_points AS (
                SELECT 
                    cc.user_id,
                    cc.challenge_template_id,
                    SUM(cf.points) AS user_points
                FROM completed_challenges cc
                JOIN challenge_flags cf ON cc.flag_id = cf.id
                WHERE cc.user_id = :user_id
                GROUP BY cc.user_id, cc.challenge_template_id
            )
            SELECT 
                COALESCE(ucp.user_points, 0) >= COALESCE(ctp.total_points, 0) AS solved
            FROM challenge_templates ct
            LEFT JOIN challenge_total_points ctp ON ctp.challenge_template_id = ct.id
            LEFT JOIN user_completed_points ucp 
                ON ucp.challenge_template_id = ct.id AND ucp.user_id = :user_id
            WHERE ct.id = :challenge_template_id
        ");
            $stmt->execute([
                ':user_id' => $this->userId,
                ':challenge_template_id' => $challengeId
            ]);
            $data = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$data) {
                return null;
            }

            return $data['solved'];
        } catch (PDOException $e) {
            $this->logger->logError("Database error in getUserChallengeData for user $this->userId and challenge $challengeId: " . $e->getMessage());
            return null;
        }
    }

    private function sendResponse($response): void
    {
        echo json_encode(['success' => true, 'data' => $response]);
    }
}

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    header('Content-Type: application/json');
    $config = require __DIR__ . '/../config/backend.config.php';

    $handler = new ExploreHandler(config: $config);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    $errorMessage = $e->getMessage();
    $logger = new Logger();

    if ($errorCode === 401) {
        $this->session->unset();
        $this->session->destroy();
        $logger->logWarning("Session destroyed due to unauthorized access");
    }

    if ($errorCode >= 500) {
        $errorMessage = 'An internal server error occurred';
        $logger->logError("Internal error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    } else {
        $logger->logError("Explore endpoint error: " . $e->getMessage());
    }

    http_response_code($errorCode);
    echo json_encode([
        'success' => false,
        'message' => $errorMessage,
        'redirect' => $errorCode === 401 ? '/login' : null
    ]);
}