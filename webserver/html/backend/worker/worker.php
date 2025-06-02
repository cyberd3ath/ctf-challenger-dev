<?php

require_once '/var/www/html/includes/db.php';
require_once '/var/www/html/includes/curlHelper.php';
require_once '/var/www/html/includes/auth.php';

class ChallengeWorker
{
    private $pdo;

    public function __construct()
    {
        $this->pdo = getPDO();
    }

    public function run()
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
            error_log("ChallengeWorker error: " . $e->getMessage());
            $this->logMessage("Error processing challenges: " . $e->getMessage());
        }
    }

    private function getExpiredChallenges()
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
            WHERE c.expires_at <= NOW()
        ");

        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function processExpiredChallenge($challenge)
    {
        $this->pdo->beginTransaction();

        try {
            $this->stopChallenge($challenge['user_id']);
            $this->markAttemptAsCompleted($challenge['user_id'], $challenge['challenge_template_id']);
            if ($this->shouldDeleteChallengeTemplate($challenge['challenge_template_id'])) {
                $this->deleteChallengeTemplate($challenge['challenge_template_id']);
            }

            $this->pdo->commit();

            error_log("Successfully processed expired challenge for user {$challenge['username']} (ID: {$challenge['user_id']})");

        } catch (Exception $e) {
            $this->pdo->rollBack();
            error_log("Failed to process expired challenge for user {$challenge['username']}: " . $e->getMessage());
            throw $e;
        }
    }

    private function stopChallenge($userId)
    {
        $result = makeBackendRequest(
            '/stop-challenge',
            'POST',
            getBackendHeaders(),
            ['user_id' => $userId]
        );

        if (!$result['success'] || $result['http_code'] !== 200) {
            throw new Exception("Failed to stop challenge: " . ($result['error'] ?? "HTTP {$result['http_code']}"));
        }
    }

    private function markAttemptAsCompleted($userId, $challengeTemplateId)
    {
        $stmt = $this->pdo->prepare("
            UPDATE completed_challenges
            SET completed_at = NOW()
            WHERE user_id = :user_id
            AND challenge_template_id = :challenge_id
            AND completed_at IS NULL
        ");
        $stmt->execute([
            'user_id' => $userId,
            'challenge_id' => $challengeTemplateId
        ]);
    }

    private function shouldDeleteChallengeTemplate($challengeTemplateId)
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

    private function deleteChallengeTemplate($challengeTemplateId)
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM completed_challenges
            WHERE challenge_template_id = :challenge_id
        ");
        $stmt->execute(['challenge_id' => $challengeTemplateId]);
        $result = makeBackendRequest(
            '/delete-machine-templates',
            'POST',
            getBackendHeaders(),
            ['challenge_id' => $challengeTemplateId]
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
                    $stmt->execute(['challenge_id' => $challengeTemplateId]);
                    break;

                case 'machine_templates':
                    $stmt = $this->pdo->prepare("
                        DELETE FROM machine_templates
                        WHERE challenge_template_id = :challenge_id
                    ");
                    $stmt->execute(['challenge_id' => $challengeTemplateId]);
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
                    $stmt->execute(['challenge_id' => $challengeTemplateId]);
                    break;

                case 'challenge_templates':
                    $stmt = $this->pdo->prepare("
                        DELETE FROM challenge_templates
                        WHERE id = :challenge_id
                    ");
                    $stmt->execute(['challenge_id' => $challengeTemplateId]);
                    break;

                default:
                    $stmt = $this->pdo->prepare("
                        DELETE FROM {$table}
                        WHERE challenge_template_id = :challenge_id
                    ");
                    $stmt->execute(['challenge_id' => $challengeTemplateId]);
                    break;
            }
        }

        $this->logMessage("Successfully deleted challenge template ID {$challengeTemplateId}");
    }

    private function logMessage($message)
    {
        echo "[" . date('Y-m-d H:i:s') . "] $message\n";
    }
}

$worker = new ChallengeWorker();
$worker->run();