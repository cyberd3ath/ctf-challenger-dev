CREATE FUNCTION get_basic_profile_data(p_user_id INT)
RETURNS TABLE (
    username TEXT,
    email TEXT,
    created_at TIMESTAMP,
    last_login TIMESTAMP,
    avatar_url TEXT,
    full_name TEXT,
    bio TEXT,
    github_url TEXT,
    twitter_url TEXT,
    website_url TEXT,
    solved_count INT,
    total_points INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH flag_counts AS (
        SELECT challenge_template_id, COUNT(*) AS total_flags
        FROM challenge_flags
        GROUP BY challenge_template_id
    ),
    user_flags AS (
        SELECT cc.challenge_template_id, COUNT(DISTINCT cc.flag_id) AS user_flag_count
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cc.flag_id = cf.id
        WHERE cc.user_id = p_user_id
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
        WHERE cc.user_id = p_user_id
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
    WHERE u.id = p_user_id;
END;
$$;


CREATE FUNCTION get_user_rank(p_user_id INT, p_user_points INT)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN (
        SELECT COUNT(*) + 1 AS user_rank
        FROM (
            SELECT u.id, COALESCE(SUM(cf.points), 0) AS points
            FROM users u
            LEFT JOIN completed_challenges cc ON cc.user_id = u.id
            LEFT JOIN challenge_flags cf ON cc.flag_id = cf.id
            GROUP BY u.id
            HAVING COALESCE(SUM(cf.points), 0) > p_user_points
                OR (COALESCE(SUM(cf.points), 0) = p_user_points AND u.id < p_user_id)
        ) ranked_users
    );
END;
$$;


CREATE FUNCTION get_profile_stats(p_user_id INT)
RETURNS TABLE (
    solved INT,
    attempts INT,
    total_points INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH flag_counts AS (
        SELECT challenge_template_id, COUNT(*) AS total_flags
        FROM challenge_flags
        GROUP BY challenge_template_id
    ),
    user_flags AS (
        SELECT cc.challenge_template_id, COUNT(DISTINCT cc.flag_id) AS user_flag_count
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cc.flag_id = cf.id
        WHERE cc.user_id = p_user_id
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
        WHERE cc.user_id = p_user_id
    )
    SELECT
        (SELECT COUNT(*) FROM solved) AS solved,
        (SELECT COUNT(DISTINCT challenge_template_id) FROM completed_challenges WHERE user_id = p_user_id) AS attempts,
        (SELECT total_points FROM total_points) AS total_points;
END;
$$;


CREATE FUNCTION get_profile_badges(p_user_id INT)
RETURNS TABLE (
    id INT,
    name TEXT,
    description TEXT,
    icon TEXT,
    color badge_color
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT b.id, b.name, b.description, b.icon, b.color
    FROM user_badges ub
    JOIN badges b ON b.id = ub.badge_id
    WHERE ub.user_id = p_user_id
    ORDER BY b.rarity DESC, ub.earned_at DESC;
END;
$$;


CREATE FUNCTION get_total_badges_count()
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN (SELECT COUNT(*) AS total FROM badges);
END;
$$;


CREATE FUNCTION get_recent_activity(p_user_id INT, p_limit INT)
RETURNS TABLE (
    challenge_id INT,
    challenge_name TEXT,
    category challenge_category,
    points INT,
    solved BOOLEAN,
    attempts INT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT,
    time_ago TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH solved_challenges AS (
        SELECT cc.challenge_template_id, MAX(cc.completed_at) as completed_at
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cc.flag_id = cf.id
        WHERE cc.user_id = p_user_id
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
        WHERE cc.user_id = p_user_id
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
                    WHEN EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - sc.completed_at)) < 24
                    THEN EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - sc.completed_at)) || ' hours ago'
                    ELSE EXTRACT(DAY FROM (CURRENT_TIMESTAMP - sc.completed_at)) || ' days ago'
                END
            WHEN ca.completed_at IS NOT NULL THEN
                CASE
                    WHEN EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - ca.completed_at)) < 24
                    THEN 'Failed ' || EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - ca.completed_at)) || ' hours ago'
                    ELSE 'Failed ' || EXTRACT(DAY FROM (CURRENT_TIMESTAMP - ca.completed_at)) || ' days ago'
                END
            ELSE
                CASE
                    WHEN EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - ca.started_at)) < 24
                    THEN 'Started ' || EXTRACT(HOUR FROM (CURRENT_TIMESTAMP - ca.started_at)) || ' hours ago'
                    ELSE 'Started ' || EXTRACT(DAY FROM (CURRENT_TIMESTAMP - ca.started_at)) || ' days ago'
                END
        END AS time_ago
    FROM challenge_templates ct
    JOIN challenge_attempts ca ON ca.challenge_template_id = ct.id
    LEFT JOIN solved_challenges sc ON sc.challenge_template_id = ct.id
    WHERE EXISTS (
        SELECT 1 FROM completed_challenges
        WHERE user_id = p_user_id AND challenge_template_id = ct.id
    )
    ORDER BY COALESCE(sc.completed_at, ca.completed_at, ca.started_at) DESC
    LIMIT p_limit;
END;
$$;


CREATE FUNCTION is_username_taken_by_other_user(
    p_user_id INT,
    p_username TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM users WHERE username = p_username AND id <> p_user_id);
END;
$$;


CREATE FUNCTION update_username(
    p_user_id INT,
    p_new_username TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE users
    SET username = p_new_username
    WHERE id = p_user_id;
END;
$$;


CREATE FUNCTION is_email_taken_by_other_user(
    p_user_id INT,
    p_email TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM users WHERE email = p_email AND id <> p_user_id);
END;
$$;


CREATE FUNCTION update_email(
    p_user_id INT,
    p_new_email TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE users
    SET email = p_new_email
    WHERE id = p_user_id;
END;
$$;


CREATE FUNCTION user_profile_exists(p_user_id INT)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM user_profiles WHERE user_id = p_user_id);
END;
$$;


CREATE FUNCTION update_full_name(
    p_user_id INT,
    p_full_name TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF user_profile_exists(p_user_id) THEN
        UPDATE user_profiles
        SET full_name = p_full_name
        WHERE user_id = p_user_id;
    ELSE
        INSERT INTO user_profiles (user_id, full_name)
        VALUES (p_user_id, p_full_name);
    END IF;
END;
$$;


CREATE FUNCTION update_bio(
    p_user_id INT,
    p_bio TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF user_profile_exists(p_user_id) THEN
        UPDATE user_profiles
        SET bio = p_bio
        WHERE user_id = p_user_id;
    ELSE
        INSERT INTO user_profiles (user_id, bio)
        VALUES (p_user_id, p_bio);
    END IF;
END;
$$;


CREATE FUNCTION update_urls(
    p_user_id INT,
    p_github_url TEXT,
    p_twitter_url TEXT,
    p_website_url TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF user_profile_exists(p_user_id) THEN
        UPDATE user_profiles
        SET github_url = p_github_url,
            twitter_url = p_twitter_url,
            website_url = p_website_url
        WHERE user_id = p_user_id;
    ELSE
        INSERT INTO user_profiles (user_id, github_url, twitter_url, website_url)
        VALUES (p_user_id, p_github_url, p_twitter_url, p_website_url);
    END IF;
END;
$$;


CREATE FUNCTION get_user_avatar(p_user_id INT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN (SELECT avatar_url FROM users WHERE id = p_user_id);
END;
$$;


CREATE FUNCTION update_user_avatar(
    p_user_id INT,
    p_avatar_url TEXT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE users
    SET avatar_url = p_avatar_url
    WHERE id = p_user_id;
END;
$$;


CREATE FUNCTION get_all_challenge_categories()
RETURNS TABLE (
    category challenge_category
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT unnest(
        enum_range(NULL::challenge_category)
    ) AS category
    ORDER BY category;
END;
$$;


CREATE FUNCTION get_challenge_count_by_categories()
RETURNS TABLE (
    category challenge_category,
    total INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        ct.category,
        COUNT(ct.id) AS total
    FROM challenge_templates ct
    GROUP BY ct.category
    ORDER BY ct.category;
END;
$$;


CREATE FUNCTION get_user_solved_challenge_count_by_categories(p_user_id INT)
RETURNS TABLE (
    category challenge_category,
    solved INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH solved_challenges AS (
        SELECT cc.challenge_template_id
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cc.flag_id = cf.id
        WHERE cc.user_id = p_user_id
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
    ORDER BY ct.category;
END;
$$;


CREATE FUNCTION get_user_disk_files_display_data(p_user_id INT)
RETURNS TABLE(
    ova_id           INT,
    proxmox_filename TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT id AS ova_id, proxmox_filename
    FROM disk_files
    WHERE user_id = p_user_id;
END;
$$;


CREATE FUNCTION delete_user_disk_files(p_user_id INT, p_ova_id INT, p_hashed_password TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_hashed_password) THEN
        DELETE FROM disk_files
        WHERE user_id = p_user_id AND id = p_ova_id;
    ELSE
        RAISE EXCEPTION 'Authentication failed: Invalid password.';
    END IF;
END;
$$;


CREATE FUNCTION delete_user_data(p_user_id INT, p_hashed_password TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_hashed_password) THEN
        DELETE FROM user_badges WHERE user_id = p_user_id;
        DELETE FROM user_profiles WHERE user_id = p_user_id;
        DELETE FROM completed_challenges WHERE user_id = p_user_id;
        DELETE FROM disk_files WHERE user_id = p_user_id;
        UPDATE vpn_static_ips SET user_id = NULL WHERE user_id = p_user_id;
        DELETE FROM users WHERE id = p_user_id;
    ELSE
        RAISE EXCEPTION 'Authentication failed: Invalid password.';
    END IF;
END;
$$;


CREATE FUNCTION get_header_data(p_user_id INT)
RETURNS TABLE (
    avatar_url TEXT,
    is_admin BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT u.avatar_url, u.is_admin
    FROM users u
    WHERE u.id = p_user_id;
END;
$$;


CREATE FUNCTION get_id_by_username(p_username TEXT)
RETURNS INT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN (SELECT id FROM users WHERE username = p_username);
END;
$$;


CREATE FUNCTION get_public_profile_data(p_user_id INT)
RETURNS TABLE (
    username TEXT,
    created_at TIMESTAMP,
    avatar_url TEXT,
    full_name TEXT,
    bio TEXT,
    github_url TEXT,
    twitter_url TEXT,
    website_url TEXT,
    solved_count INT,
    total_points INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH flag_counts AS (
        SELECT challenge_template_id, COUNT(*) AS total_flags
        FROM challenge_flags
        GROUP BY challenge_template_id
    ),
    user_flags AS (
        SELECT cc.challenge_template_id, COUNT(DISTINCT cc.flag_id) AS user_flag_count
        FROM completed_challenges cc
        JOIN challenge_flags cf ON cc.flag_id = cf.id
        WHERE cc.user_id = p_user_id
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
        WHERE cc.user_id = p_user_id
    )
    SELECT
        u.username,
        u.created_at,
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
    WHERE u.id = p_user_id;
END;
$$;


CREATE FUNCTION get_active_challenge_templates_by_category()
RETURNS TABLE (
    category challenge_category,
    total INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT category, COUNT(*) as total
    FROM challenge_templates
    WHERE is_active = true
    GROUP BY category
    ORDER BY category;
END;
$$;

CREATE FUNCTION get_user_earned_badges_data(p_user_id INT)
RETURNS TABLE (
    id INT,
    name TEXT,
    description TEXT,
    icon TEXT,
    color badge_color
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT b.id, b.name, b.description, b.icon, b.color
    FROM user_badges ub
    JOIN badges b ON b.id = ub.badge_id
    WHERE ub.user_id = p_user_id
    ORDER BY b.rarity DESC, ub.earned_at DESC, b.id;
END;
$$;
