<?php

// @codeCoverageIgnoreStart
if (defined('PHPUNIT_RUNNING')) 
    require_once __DIR__ . '/../../vendor/autoload.php';
else
    require_once '/var/www/html/vendor/autoload.php';
// @codeCoverageIgnoreEnd


class ChallengeWorker
{
    private PDO $pdo;
    private IDatabaseHelper $databaseHelper;
    private ICurlHelper $curlHelper;
    private IAuthHelper $authHelper;
    private bool $logErrors;
    private ISystem $system;

    public function __construct(
        IDatabaseHelper $databaseHelper = null,
        ICurlHelper $curlHelper = null,
        IAuthHelper $authHelper = null,
        
        bool $logErrors = true,
        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env(),
        ILogger $logger = null
        
    ) {        
        $this->logErrors = $logErrors;
        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->curlHelper = $curlHelper ?? new CurlHelper($env);
        $this->authHelper = $authHelper ?? new AuthHelper($logger, $system, $env);

        $this->pdo = $this->databaseHelper->getPDO();
        $this->system = $system;
    }

    public function run(): void
    {
        try {
            $expiredChallenges = $this->getExpiredChallenges();

            if (empty($expiredChallenges)) {
                $this->logMessage("No expired challenges found.");
                return;
            }

            foreach ($expiredChallenges as $challenge) {
                $this->processExpiredChallenge($challenge);
            }

            $this->logMessage("Successfully processed " . count($expiredChallenges) . " expired challenges.");

        } catch (Exception $e) {
            $this->logError("ChallengeWorker error: " . $e->getMessage());
            $this->logMessage("Error processing challenges: " . $e->getMessage());
        }
    }

    private function getExpiredChallenges(): array
    {
        $stmt = $this->pdo->prepare("
            SELECT
                u.id AS user_id,
                u.username,
                c.id AS challenge_id,
                c.challenge_template_id,
                c.expires_at
            FROM users u
            JOIN challenges c ON u.running_challenge = c.id
            WHERE c.expires_at <= CURRENT_TIMESTAMP
        ");

        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @throws Exception
     */
    private function processExpiredChallenge($challenge): void
    {
        $this->pdo->beginTransaction();

        try {
            $this->stopChallenge($challenge['user_id']);
            $this->markAttemptAsCompleted($challenge['user_id'], $challenge['challenge_template_id']);
            if ($this->shouldDeleteChallengeTemplate($challenge['challenge_template_id'])) {
                $this->deleteChallengeTemplate($challenge['challenge_template_id']);
            }

            $this->pdo->commit();

            $this->logError("Successfully processed expired challenge for user {$challenge['username']} (ID: {$challenge['user_id']})");

        } catch (Exception $e) {
            $this->pdo->rollBack();
            $this->logError("Failed to process expired challenge for user {$challenge['username']}: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * @throws Exception
     */
    private function stopChallenge($userId): void
    {
        $result = $this->curlHelper->makeBackendRequest(
            '/stop-challenge',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['user_id' => $userId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            throw new Exception("Failed to stop challenge: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
        }
    }

    private function markAttemptAsCompleted($userId, $challengeTemplateId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE completed_challenges
            SET completed_at = CURRENT_TIMESTAMP
            WHERE user_id = :user_id
            AND challenge_template_id = :challenge_id
            AND completed_at IS NULL
        ");
        $stmt->execute([
            'user_id' => $userId,
            'challenge_id' => $challengeTemplateId
        ]);
    }

    private function shouldDeleteChallengeTemplate($challengeTemplateId): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*)
            FROM challenges
            WHERE challenge_template_id = :template_id
        ");
        $stmt->execute(['template_id' => $challengeTemplateId]);
        $remainingInstances = $stmt->fetchColumn();

        $stmt = $this->pdo->prepare("
            SELECT marked_for_deletion
            FROM challenge_templates
            WHERE id = :template_id
        ");
        $stmt->execute(['template_id' => $challengeTemplateId]);
        $markedForDeletion = $stmt->fetchColumn();

        return $markedForDeletion && $remainingInstances === 0;
    }

    /**
     * @throws Exception
     */
    private function deleteChallengeTemplate($challengeTemplateId): void
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM completed_challenges
            WHERE challenge_template_id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeTemplateId]);
        $result = $this->curlHelper->makeBackendRequest(
            '/delete-machine-templates',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['challenge_id' => $challengeTemplateId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            throw new Exception("Failed to delete VM templates: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
        }

        $stmt = $this->pdo->prepare("
            DELETE FROM network_templates nt
            WHERE EXISTS(
                SELECT 1
                FROM network_connection_templates nct
                JOIN machine_templates mt ON nct.machine_template_id = mt.id
                WHERE nct.network_template_id = nt.id
                AND mt.challenge_template_id = :challenge_id
            )
        ");
        $stmt->execute(['challenge_id' => $challengeTemplateId]);

        $stmt = $this->pdo->prepare("
            DELETE FROM challenge_templates
            WHERE id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeTemplateId]);

        $this->logMessage("Successfully deleted challenge template ID $challengeTemplateId");
    }

    private function logMessage($message): void
    {
        echo "[" . $this->system->date('Y-m-d H:i:s') . "] $message\n";
    }
    
    private function logError($message): void
    {
        if(!$this->logErrors)
            return;

        // @codeCoverageIgnoreStart
        error_log($message);
        // @codeCoverageIgnoreEnd
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

$worker = new ChallengeWorker();
$worker->run();

// @codeCoverageIgnoreEnd