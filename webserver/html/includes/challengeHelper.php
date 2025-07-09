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

function getSolvedLeaderboard(PDO $pdo, int $challengeTemplateId): array
{
    $stmt = $pdo->prepare("
        WITH possible_flags AS (
            SELECT cf.id AS flag_id
            FROM challenge_flags cf
            WHERE cf.challenge_template_id = :challenge_template_id
        ),
        user_submissions AS (
            SELECT cc.user_id, cc.flag_id, cc.completed_at, cc.started_at
            FROM completed_challenges cc
            WHERE cc.challenge_template_id = :challenge_template_id
        ),
        users_who_solved AS (
            SELECT us.user_id
            FROM (SELECT DISTINCT user_id FROM user_submissions) us
            WHERE NOT EXISTS (
                SELECT 1
                FROM possible_flags pf
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM user_submissions s
                    WHERE s.user_id = us.user_id AND s.flag_id = pf.flag_id
                )
            )
        ),
        user_eola AS (
            SELECT uws.user_id,
                   (SELECT MAX(us3.completed_at)
                    FROM user_submissions us3
                    WHERE us3.user_id = uws.user_id AND us3.flag_id IS NOT NULL) AS end_of_last_interval
            FROM users_who_solved uws
        ),
        intervals AS (
            SELECT us.user_id,
                   COALESCE(us.completed_at, NOW()) - us.started_at AS intvl
            FROM user_submissions us
            JOIN user_eola e ON us.user_id = e.user_id
            WHERE COALESCE(us.completed_at, NOW()) <= e.end_of_last_interval
        ),
        summed AS (
            SELECT user_id, EXTRACT(EPOCH FROM SUM(intvl))::BIGINT AS total_seconds
            FROM intervals
            GROUP BY user_id
        ),
        ranked AS (
            SELECT u.username, u.avatar_url, s.total_seconds,
                   ROW_NUMBER() OVER (ORDER BY s.total_seconds ASC) AS rank
            FROM summed s
            JOIN users u ON u.id = s.user_id
        )
        SELECT username, avatar_url, total_seconds, rank
        FROM ranked
        ORDER BY rank
        LIMIT 10;
    ");
    $stmt->execute(['challenge_template_id' => $challengeTemplateId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
