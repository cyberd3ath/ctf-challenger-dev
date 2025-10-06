CREATE FUNCTION get_user_badges_data(
    p_user_id INT
)
RETURNS TABLE (
    id INT,
    name TEXT,
    description TEXT,
    icon TEXT,
    rarity badge_rarity,
    requirements TEXT,
    earned_at TIMESTAMP,
    earned BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        b.id,
        b.name,
        b.description,
        b.icon,
        b.rarity,
        b.requirements,
        ub.earned_at,
        CASE WHEN ub.user_id IS NULL THEN false ELSE true END as earned
    FROM badges b
    LEFT JOIN user_badges ub ON ub.badge_id = b.id AND ub.user_id = p_user_id
    ORDER BY b.rarity DESC, b.name, b.id;
END;
$$;


CREATE FUNCTION get_user_solved_challenge_count(
    p_user_id INT
)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH user_completed_flags AS (
        SELECT
            user_id,
            challenge_template_id,
            flag_id
        FROM completed_challenges
        WHERE user_id = p_user_id
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
    SELECT COUNT(*)
    FROM user_solved_challenges
    WHERE user_id = p_user_id;
END;
$$;


CREATE FUNCTION get_user_solved_challenge_count_in_category(
    p_user_id INT,
    p_category challenge_category
)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH user_completed_flags AS (
        SELECT
            cc.user_id,
            cc.challenge_template_id,
            cc.flag_id
        FROM completed_challenges cc
        WHERE cc.user_id = p_user_id
    ),
    challenge_total_flags AS (
        SELECT
            cf.challenge_template_id,
            COUNT(*) as total_flags
        FROM challenge_flags cf
        JOIN challenge_templates ct ON ct.id = cf.challenge_template_id
        WHERE ct.category = p_category
        GROUP BY cf.challenge_template_id
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
    SELECT COUNT(*)
    FROM user_solved_challenges
    WHERE user_id = p_user_id;
END;
$$;


CREATE FUNCTION get_user_total_points(
    p_user_id INT
)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT COALESCE(SUM(cf.points), 0)
    FROM completed_challenges cc
    JOIN challenge_flags cf ON cf.id = cc.flag_id
    WHERE cc.user_id = p_user_id;
END;
$$;


CREATE FUNCTION get_user_earned_badges_count_exclude_one(
    p_user_id INT,
    p_exclude_badge_id INT
)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT COUNT(*)
    FROM user_badges ub
    JOIN badges b ON b.id = ub.badge_id
    WHERE ub.user_id = p_user_id
    AND b.id != p_exclude_badge_id;
END;
$$;


CREATE FUNCTION get_total_badge_count_exclude_one(
    p_exclude_badge_id INT
)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM badges WHERE id != p_exclude_badge_id);
END;
$$;


CREATE FUNCTION get_total_badge_count_and_user_earned_count(
    p_user_id INT
)
RETURNS TABLE (
    total_badges INT,
    earned_badges INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        (SELECT COUNT(*) FROM badges) AS total_badges,
        (SELECT COUNT(*) FROM user_badges WHERE user_id = p_user_id) AS earned_badges;
END;
$$;





