<?php
declare(strict_types=1);

function isChallengeSolved(PDO $pdo, int $userId, int $challengeId): bool
{
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(DISTINCT cf.id) AS total_flags,
            COUNT(DISTINCT cc.flag_id) AS flags_completed,
            (COUNT(DISTINCT cc.flag_id) >= COUNT(DISTINCT cf.id)) AS is_solved
        FROM challenge_flags cf
        LEFT JOIN completed_challenges cc ON 
            cf.id = cc.flag_id AND 
            cc.user_id = :user_id AND
            cc.challenge_template_id = :challenge_id
        WHERE cf.challenge_template_id = :challenge_id
    ");
    $stmt->execute([
        'user_id' => $userId,
        'challenge_id' => $challengeId
    ]);
    $solvedData = $stmt->fetch(PDO::FETCH_ASSOC);
    return (bool)($solvedData['is_solved'] ?? false);
}

function getElapsedSecondsForChallenge(PDO $pdo, int $userId, int $challengeId) :int
{
    $stmt = $pdo->prepare("
            WITH possible_flags AS (
                SELECT cf.id AS flag_id
                FROM challenge_flags cf
                WHERE cf.challenge_template_id = :challenge_template_id
            ),
            submitted_flags AS (
                SELECT cc.flag_id AS flag_id
                FROM completed_challenges cc
                WHERE cc.user_id = :user_id
                  AND cc.challenge_template_id = :challenge_template_id
                  AND cc.flag_id IS NOT NULL
            ),
            eola AS (
                SELECT CASE
                    WHEN NOT EXISTS (
                        SELECT 1 
                        FROM possible_flags pf
                        WHERE NOT EXISTS (
                            SELECT 1 
                            FROM submitted_flags sf
                            WHERE sf.flag_id = pf.flag_id
                        )
                    ) THEN 
                        (SELECT MAX(cc.completed_at)
                         FROM completed_challenges cc
                         WHERE cc.flag_id IS NOT NULL
                        )
                    ELSE NOW()
                END AS end_of_last_interval
            ),
            intervals AS (
                SELECT COALESCE(cc.completed_at, NOW()) - cc.started_at AS intvl
                FROM completed_challenges cc, eola
                WHERE cc.user_id = :user_id
                  AND cc.challenge_template_id = :challenge_template_id
                  AND (COALESCE(cc.completed_at, NOW()) <= eola.end_of_last_interval)
            )
            SELECT EXTRACT(EPOCH FROM SUM(intervals.intvl))::BIGINT AS total_seconds FROM intervals;
        ");
    $stmt->execute([
        'user_id' => $userId,
        'challenge_template_id' => $challengeId
    ]);

    return (int)$stmt->fetchColumn();
}